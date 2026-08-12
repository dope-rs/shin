use crate::identity::cert::ext;
use crate::identity::chain;
use crate::identity::chain::search;
use ext::scope;

enum NameConstraintsRef<'a> {
    Parsed(scope::NameConstraints<'a>),
    Prepared(&'a chain::PreparedNameConstraints),
}

impl NameConstraintsRef<'_> {
    fn has_unsupported(&self) -> bool {
        match self {
            Self::Parsed(constraints) => {
                constraints.permitted.has_unsupported() || constraints.excluded.has_unsupported()
            }
            Self::Prepared(constraints) => constraints.has_unsupported(),
        }
    }

    fn permitted_dns_is_empty(&self) -> bool {
        match self {
            Self::Parsed(constraints) => constraints.permitted.dns_is_empty(),
            Self::Prepared(constraints) => constraints.permitted_dns().is_empty(),
        }
    }

    fn permitted_ip_is_empty(&self) -> bool {
        match self {
            Self::Parsed(constraints) => constraints.permitted.ip_is_empty(),
            Self::Prepared(constraints) => constraints.permitted_ip().is_empty(),
        }
    }

    fn permitted_dns_matches(&self, name: &[u8]) -> Result<bool, chain::Error> {
        match self {
            Self::Parsed(constraints) => Ok(constraints.permitted.dns_matches(name)?),
            Self::Prepared(constraints) => constraints
                .permitted_dns()
                .any(|subtree| scope::GeneralName::dns_in_subtree(name, subtree)),
        }
    }

    fn excluded_dns_matches(&self, name: &[u8]) -> Result<bool, chain::Error> {
        match self {
            Self::Parsed(constraints) => Ok(constraints.excluded.dns_matches(name)?),
            Self::Prepared(constraints) => constraints
                .excluded_dns()
                .any(|subtree| scope::GeneralName::dns_in_subtree(name, subtree)),
        }
    }

    fn permitted_ip_matches(&self, address: &[u8]) -> Result<bool, chain::Error> {
        match self {
            Self::Parsed(constraints) => Ok(constraints.permitted.ip_matches(address)?),
            Self::Prepared(constraints) => constraints
                .permitted_ip()
                .any(|network| scope::GeneralName::ip_in_subtree(address, network)),
        }
    }

    fn excluded_ip_matches(&self, address: &[u8]) -> Result<bool, chain::Error> {
        match self {
            Self::Parsed(constraints) => Ok(constraints.excluded.ip_matches(address)?),
            Self::Prepared(constraints) => constraints
                .excluded_ip()
                .any(|network| scope::GeneralName::ip_in_subtree(address, network)),
        }
    }
}

fn check_name_constraints(
    constraints: NameConstraintsRef<'_>,
    subordinates: search::Path<'_, '_>,
) -> Result<(), chain::Error> {
    if constraints.has_unsupported() {
        return Err(chain::Error::NameConstraintViolation);
    }
    for subordinate in subordinates.iter() {
        let subordinate = subordinate?;
        if subordinate.primary.is_empty() {
            continue;
        }
        let names = scope::GeneralNames::from_validated_contents(subordinate.primary);
        for name in names.iter() {
            match name? {
                scope::GeneralName::DnsName(dns_name) => {
                    if constraints.excluded_dns_matches(dns_name)? {
                        return Err(chain::Error::NameConstraintViolation);
                    }
                    if !constraints.permitted_dns_is_empty()
                        && !constraints.permitted_dns_matches(dns_name)?
                    {
                        return Err(chain::Error::NameConstraintViolation);
                    }
                }
                scope::GeneralName::IpAddress(address) => {
                    if constraints.excluded_ip_matches(address)? {
                        return Err(chain::Error::NameConstraintViolation);
                    }
                    if !constraints.permitted_ip_is_empty()
                        && !constraints.permitted_ip_matches(address)?
                    {
                        return Err(chain::Error::NameConstraintViolation);
                    }
                }
                scope::GeneralName::Other { .. } => {}
            }
        }
    }
    Ok(())
}

const BASIC_CONSTRAINTS: u16 = 1 << 0;
const CERTIFICATE_AUTHORITY: u16 = 1 << 1;
const KEY_USAGE: u16 = 1 << 2;
const DIGITAL_SIGNATURE: u16 = 1 << 3;
const KEY_CERT_SIGN: u16 = 1 << 4;
const EXTENDED_KEY_USAGE: u16 = 1 << 5;
const SERVER_AUTH: u16 = 1 << 6;
const ANY_EXTENDED_KEY_USAGE: u16 = 1 << 7;
const NO_PATH_LIMIT: u8 = u8::MAX;

#[derive(Clone, Copy)]
enum Status {
    Raw,
    Valid,
    Invalid(chain::Error),
}

/// A compact policy profile whose primary slice changes from raw extensions
/// to validated subjectAltName contents when first prepared.
#[derive(Clone, Copy)]
pub(super) struct Profile<'a> {
    primary: &'a [u8],
    name_constraints: &'a [u8],
    flags: u16,
    path_limit: u8,
    status: Status,
}

const _: () = assert!(core::mem::size_of::<Profile<'static>>() <= 40);

impl<'a> Profile<'a> {
    pub(super) fn raw(extensions_der: Option<&'a [u8]>) -> Self {
        Self {
            primary: extensions_der.unwrap_or(&[]),
            name_constraints: &[],
            flags: 0,
            path_limit: NO_PATH_LIMIT,
            status: Status::Raw,
        }
    }

    pub(super) fn prepare(&mut self) -> Result<&Self, chain::Error> {
        match self.status {
            Status::Valid => return Ok(self),
            Status::Invalid(error) => return Err(error),
            Status::Raw => {}
        }
        let prepared = Self::parse(self.primary);
        match prepared {
            Ok(profile) => {
                *self = profile;
                Ok(self)
            }
            Err(error) => {
                *self = Self {
                    primary: &[],
                    name_constraints: &[],
                    flags: 0,
                    path_limit: NO_PATH_LIMIT,
                    status: Status::Invalid(error),
                };
                Err(error)
            }
        }
    }

    pub(super) fn resolve(&self) -> Result<&Self, chain::Error> {
        match self.status {
            Status::Valid => Ok(self),
            Status::Invalid(error) => Err(error),
            Status::Raw => Err(chain::Error::Parse),
        }
    }

    fn parse(exts: &'a [u8]) -> Result<Self, chain::Error> {
        let mut basic_constraints = None;
        let mut key_usage = None;
        let mut eku = None::<(bool, bool)>;
        let mut name_constraints = &[][..];
        let mut san = &[][..];
        for extension in ext::ExtensionIter::new(exts) {
            let extension = extension?;
            if extension.critical && !ext::ExtensionEntry::is_handled(extension.oid) {
                return Err(chain::Error::UnhandledCriticalExtension);
            }
            if extension.oid.is(ext::OID_BASIC_CONSTRAINTS) {
                basic_constraints = Some(ext::BasicConstraints::parse(extension.value)?);
            } else if extension.oid.is(ext::OID_KEY_USAGE) {
                key_usage = Some(ext::KeyUsage::parse(extension.value)?);
            } else if extension.oid.is(ext::OID_EXTENDED_KEY_USAGE) {
                let mut server_auth = false;
                let mut any = false;
                for oid in ext::ExtendedKeyUsages::parse(extension.value)?.iter() {
                    let oid = oid?;
                    server_auth |= oid.is(ext::OID_EKU_SERVER_AUTH);
                    any |= oid.is(ext::OID_EKU_ANY);
                }
                eku = Some((server_auth, any));
            } else if extension.oid.is(ext::OID_NAME_CONSTRAINTS) {
                scope::NameConstraints::parse(extension.value)?;
                name_constraints = extension.value;
            } else if extension.oid.is(ext::OID_SUBJECT_ALT_NAME) {
                san = scope::GeneralNames::parse(extension.value)?.contents();
            }
        }

        let mut flags = 0;
        let mut path_limit = NO_PATH_LIMIT;
        if let Some(constraints) = basic_constraints {
            flags |= BASIC_CONSTRAINTS;
            if constraints.ca {
                flags |= CERTIFICATE_AUTHORITY;
            }
            if let Some(limit) = constraints.path_len_constraint {
                path_limit = limit.min(chain::MAX_LEN as u64) as u8;
            }
        }
        if let Some(usage) = key_usage {
            flags |= KEY_USAGE;
            if usage.has(ext::KeyUsage::DIGITAL_SIGNATURE) {
                flags |= DIGITAL_SIGNATURE;
            }
            if usage.has(ext::KeyUsage::KEY_CERT_SIGN) {
                flags |= KEY_CERT_SIGN;
            }
        }
        if let Some((server_auth, any)) = eku {
            flags |= EXTENDED_KEY_USAGE;
            if server_auth {
                flags |= SERVER_AUTH;
            }
            if any {
                flags |= ANY_EXTENDED_KEY_USAGE;
            }
        }
        Ok(Self {
            primary: san,
            name_constraints,
            flags,
            path_limit,
            status: Status::Valid,
        })
    }

    pub(super) fn check_leaf(&self, hostname_dns_id: &[u8]) -> Result<(), chain::Error> {
        self.resolve()?;
        self.check_end_entity()?;
        self.check_server_auth()?;
        self.check_hostname(hostname_dns_id)
    }

    pub(super) fn check_issuer(
        &self,
        subordinates: search::Path<'_, '_>,
        subject_position: usize,
    ) -> Result<(), chain::Error> {
        self.resolve()?;
        self.check_issuer_is_ca()?;
        self.check_ca_eku()?;
        self.check_path_len(subject_position)?;
        self.check_name_constraints(subordinates)
    }

    pub(super) fn check_name_constraints_der(
        name_constraints_der: &[u8],
        subordinates: search::Path<'_, '_>,
    ) -> Result<(), chain::Error> {
        let constraints = scope::NameConstraints::parse(name_constraints_der)?;
        check_name_constraints(NameConstraintsRef::Parsed(constraints), subordinates)
    }

    pub(super) fn check_prepared_name_constraints(
        constraints: &chain::PreparedNameConstraints,
        subordinates: search::Path<'_, '_>,
    ) -> Result<(), chain::Error> {
        check_name_constraints(NameConstraintsRef::Prepared(constraints), subordinates)
    }

    fn check_ca_eku(&self) -> Result<(), chain::Error> {
        if self.flags & EXTENDED_KEY_USAGE == 0 {
            return Ok(());
        }
        if self.flags & (SERVER_AUTH | ANY_EXTENDED_KEY_USAGE) != 0 {
            Ok(())
        } else {
            Err(chain::Error::NoServerAuth)
        }
    }

    fn check_name_constraints(
        &self,
        subordinates: search::Path<'_, '_>,
    ) -> Result<(), chain::Error> {
        if self.name_constraints.is_empty() {
            return Ok(());
        }
        let constraints = scope::NameConstraints::parse(self.name_constraints)?;
        check_name_constraints(NameConstraintsRef::Parsed(constraints), subordinates)
    }

    fn check_end_entity(&self) -> Result<(), chain::Error> {
        if self.flags & CERTIFICATE_AUTHORITY != 0 {
            return Err(chain::Error::NotEndEntity);
        }
        if self.flags & KEY_USAGE != 0 && self.flags & DIGITAL_SIGNATURE == 0 {
            return Err(chain::Error::LeafKeyUsageInvalid);
        }
        Ok(())
    }

    fn check_server_auth(&self) -> Result<(), chain::Error> {
        if self.flags & EXTENDED_KEY_USAGE == 0 {
            return Ok(());
        }
        if self.flags & SERVER_AUTH != 0 {
            Ok(())
        } else {
            Err(chain::Error::NoServerAuth)
        }
    }

    fn check_hostname(&self, host: &[u8]) -> Result<(), chain::Error> {
        use crate::identity::Hostname;
        if self.primary.is_empty() {
            return Err(chain::Error::HostnameMismatch);
        }
        let names = scope::GeneralNames::from_validated_contents(self.primary);
        match Hostname::new(host).parse_ip() {
            Some(target) => {
                for name in names.iter() {
                    if matches!(
                        name?,
                        scope::GeneralName::IpAddress(pattern)
                            if Hostname::new(&target).matches_ip(pattern)
                    ) {
                        return Ok(());
                    }
                }
            }
            None => {
                for name in names.iter() {
                    if matches!(
                        name?,
                        scope::GeneralName::DnsName(pattern)
                            if Hostname::new(host).matches_dns(pattern)
                    ) {
                        return Ok(());
                    }
                }
            }
        }
        Err(chain::Error::HostnameMismatch)
    }

    fn check_issuer_is_ca(&self) -> Result<(), chain::Error> {
        if self.flags & BASIC_CONSTRAINTS == 0 || self.flags & CERTIFICATE_AUTHORITY == 0 {
            return Err(chain::Error::IssuerNotCa);
        }
        if self.flags & KEY_USAGE != 0 && self.flags & KEY_CERT_SIGN == 0 {
            return Err(chain::Error::NoKeyCertSign);
        }
        Ok(())
    }

    fn check_path_len(&self, subject_position: usize) -> Result<(), chain::Error> {
        if subject_position > usize::from(self.path_limit) {
            return Err(chain::Error::PathLenExceeded);
        }
        Ok(())
    }
}
