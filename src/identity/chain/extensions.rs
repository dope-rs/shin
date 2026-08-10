use crate::identity;
use crate::identity::cert;
use crate::identity::cert::ext;
use crate::identity::chain;

/// Every extension a chain check needs, parsed in one O(exts) pass that also
/// rejects duplicate and unhandled-critical extensions.
pub(super) struct Extensions<'a> {
    basic_constraints: Option<ext::BasicConstraints>,
    key_usage: Option<ext::KeyUsage>,
    eku_der: Option<&'a [u8]>,
    name_constraints_der: Option<&'a [u8]>,
    san_der: Option<&'a [u8]>,
}

impl<'a> Extensions<'a> {
    pub(super) fn parse(cert: &cert::Cert<'a>) -> Result<Self, chain::Error> {
        let exts = cert.tbs.extensions_der.unwrap_or(&[]);
        let mut seen = arrayvec::ArrayVec::<&[u8], 64>::new();
        let mut basic_constraints = None;
        let mut key_usage = None;
        let mut eku_der = None;
        let mut name_constraints_der = None;
        let mut san_der = None;
        for extension in ext::ExtensionIter::new(exts) {
            let extension = extension?;
            if seen.contains(&extension.oid) {
                return Err(chain::Error::DuplicateExtension);
            }
            seen.try_push(extension.oid)
                .map_err(|_| chain::Error::Parse)?;
            if extension.critical && !ext::ExtensionEntry::is_handled(extension.oid) {
                return Err(chain::Error::UnhandledCriticalExtension);
            }
            if extension.oid == ext::OID_BASIC_CONSTRAINTS {
                basic_constraints = Some(ext::BasicConstraints::parse(extension.value)?);
            } else if extension.oid == ext::OID_KEY_USAGE {
                key_usage = Some(ext::KeyUsage::parse(extension.value)?);
            } else if extension.oid == ext::OID_EXTENDED_KEY_USAGE {
                ext::KeyUsage::parse_extended(extension.value)?;
                eku_der = Some(extension.value);
            } else if extension.oid == ext::OID_NAME_CONSTRAINTS {
                ext::NameConstraints::parse(extension.value)?;
                name_constraints_der = Some(extension.value);
            } else if extension.oid == ext::OID_SUBJECT_ALT_NAME {
                ext::GeneralName::parse_alt_names(extension.value)?;
                san_der = Some(extension.value);
            }
        }
        Ok(Self {
            basic_constraints,
            key_usage,
            eku_der,
            name_constraints_der,
            san_der,
        })
    }

    pub(super) fn check_leaf(&self, hostname_dns_id: &[u8]) -> Result<(), chain::Error> {
        self.check_end_entity()?;
        self.check_server_auth()?;
        self.check_hostname(hostname_dns_id)
    }

    pub(super) fn check_issuer(
        &self,
        parsed: &[Self],
        subordinate_indices: &[usize],
        subject_position: usize,
    ) -> Result<(), chain::Error> {
        self.check_issuer_is_ca()?;
        self.check_ca_eku()?;
        self.check_path_len(subject_position)?;
        self.check_name_constraints(parsed, subordinate_indices)
    }

    pub(super) fn check_name_constraints_der(
        name_constraints_der: &[u8],
        parsed: &[Self],
        subordinate_indices: &[usize],
    ) -> Result<(), chain::Error> {
        let constraints = ext::NameConstraints::parse(name_constraints_der)?;
        if constraints.permitted.has_unsupported || constraints.excluded.has_unsupported {
            return Err(chain::Error::NameConstraintViolation);
        }
        for &index in subordinate_indices {
            let Some(san_der) = parsed[index].san_der else {
                continue;
            };
            for name in ext::GeneralName::parse_alt_names(san_der)? {
                match name {
                    ext::GeneralName::DnsName(dns_name) => {
                        if constraints
                            .excluded
                            .dns
                            .iter()
                            .any(|excluded| Self::dns_in_subtree(dns_name, excluded))
                        {
                            return Err(chain::Error::NameConstraintViolation);
                        }
                        if !constraints.permitted.dns.is_empty()
                            && !constraints
                                .permitted
                                .dns
                                .iter()
                                .any(|permitted| Self::dns_in_subtree(dns_name, permitted))
                        {
                            return Err(chain::Error::NameConstraintViolation);
                        }
                    }
                    ext::GeneralName::IpAddress(address) => {
                        if constraints
                            .excluded
                            .ip
                            .iter()
                            .any(|excluded| Self::ip_in_subtree(address, excluded))
                        {
                            return Err(chain::Error::NameConstraintViolation);
                        }
                        if !constraints.permitted.ip.is_empty()
                            && !constraints
                                .permitted
                                .ip
                                .iter()
                                .any(|network| Self::ip_in_subtree(address, network))
                        {
                            return Err(chain::Error::NameConstraintViolation);
                        }
                    }
                    ext::GeneralName::Other { .. } => {}
                }
            }
        }
        Ok(())
    }

    fn check_ca_eku(&self) -> Result<(), chain::Error> {
        use crate::identity::cert::ext::OID_EKU_ANY;
        let Some(eku_der) = self.eku_der else {
            return Ok(());
        };
        let usages = ext::KeyUsage::parse_extended(eku_der)?;
        if usages.contains(&ext::OID_EKU_SERVER_AUTH) || usages.contains(&OID_EKU_ANY) {
            Ok(())
        } else {
            Err(chain::Error::NoServerAuth)
        }
    }

    fn check_name_constraints(
        &self,
        parsed: &[Self],
        subordinate_indices: &[usize],
    ) -> Result<(), chain::Error> {
        match self.name_constraints_der {
            Some(der) => Self::check_name_constraints_der(der, parsed, subordinate_indices),
            None => Ok(()),
        }
    }

    fn check_end_entity(&self) -> Result<(), chain::Error> {
        if let Some(constraints) = self.basic_constraints
            && constraints.ca
        {
            return Err(chain::Error::NotEndEntity);
        }
        if let Some(usage) = self.key_usage
            && !usage.has(ext::KeyUsage::DIGITAL_SIGNATURE)
        {
            return Err(chain::Error::LeafKeyUsageInvalid);
        }
        Ok(())
    }

    fn check_server_auth(&self) -> Result<(), chain::Error> {
        let Some(eku_der) = self.eku_der else {
            return Ok(());
        };
        let usages = ext::KeyUsage::parse_extended(eku_der)?;
        if usages.contains(&ext::OID_EKU_SERVER_AUTH) {
            Ok(())
        } else {
            Err(chain::Error::NoServerAuth)
        }
    }

    fn check_hostname(&self, host: &[u8]) -> Result<(), chain::Error> {
        use crate::identity::Hostname;
        let Some(san_der) = self.san_der else {
            return Err(chain::Error::HostnameMismatch);
        };
        let names = ext::GeneralName::parse_alt_names(san_der)?;
        match Hostname::new(host).parse_ip() {
            Some(target) => {
                if names.iter().any(|name| {
                    matches!(
                        name,
                        ext::GeneralName::IpAddress(pattern)
                            if Hostname::new(&target).matches_ip(pattern)
                    )
                }) {
                    return Ok(());
                }
            }
            None => {
                if names.iter().any(|name| {
                    matches!(
                        name,
                        ext::GeneralName::DnsName(pattern)
                            if Hostname::new(host).matches_dns(pattern)
                    )
                }) {
                    return Ok(());
                }
            }
        }
        Err(chain::Error::HostnameMismatch)
    }

    fn check_issuer_is_ca(&self) -> Result<(), chain::Error> {
        let constraints = self.basic_constraints.ok_or(chain::Error::IssuerNotCa)?;
        if !constraints.ca {
            return Err(chain::Error::IssuerNotCa);
        }
        if let Some(usage) = self.key_usage
            && !usage.has(ext::KeyUsage::KEY_CERT_SIGN)
        {
            return Err(chain::Error::NoKeyCertSign);
        }
        Ok(())
    }

    fn check_path_len(&self, subject_position: usize) -> Result<(), chain::Error> {
        if let Some(constraints) = self.basic_constraints
            && let Some(max_following) = constraints.path_len_constraint
            && subject_position as u64 > max_following
        {
            return Err(chain::Error::PathLenExceeded);
        }
        Ok(())
    }

    fn dns_in_subtree(name: &[u8], constraint: &[u8]) -> bool {
        if constraint.is_empty() {
            return true;
        }
        let (constraint, subdomains_only) = match constraint.split_first() {
            Some((b'.', rest)) => (rest, true),
            _ => (constraint, false),
        };
        if !subdomains_only && Self::ascii_case_eq(name, constraint) {
            return true;
        }
        name.len() > constraint.len()
            && name[name.len() - constraint.len() - 1] == b'.'
            && Self::ascii_case_eq(&name[name.len() - constraint.len()..], constraint)
    }

    fn ip_in_subtree(address: &[u8], network_and_mask: &[u8]) -> bool {
        if network_and_mask.len() != address.len() * 2 {
            return false;
        }
        let (network, mask) = network_and_mask.split_at(address.len());
        address
            .iter()
            .zip(network)
            .zip(mask)
            .all(|((address, network), mask)| (address & mask) == (network & mask))
    }

    fn ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }

    pub(super) fn check_validity(
        certificate: &cert::Cert<'_>,
        now: identity::UnixTime,
    ) -> Result<(), chain::Error> {
        let not_before = identity::UnixTime::from_time_value(&certificate.tbs.validity.not_before)?;
        let not_after = identity::UnixTime::from_time_value(&certificate.tbs.validity.not_after)?;
        if now < not_before {
            return Err(chain::Error::NotYetValid);
        }
        if now > not_after {
            return Err(chain::Error::Expired);
        }
        Ok(())
    }
}
