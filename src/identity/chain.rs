use arrayvec::ArrayVec;

use crate::identity::cert::ext::{
    BasicConstraints, ExtensionEntry, ExtensionIter, GeneralName, KeyUsage, NameConstraints,
    OID_EKU_ANY, OID_EKU_SERVER_AUTH, OID_EXT_BASIC_CONSTRAINTS, OID_EXT_EXTENDED_KEY_USAGE,
    OID_EXT_KEY_USAGE, OID_EXT_NAME_CONSTRAINTS, OID_EXT_SAN,
};
use crate::identity::cert::{Cert, CertError, SubjectPublicKeyInfo, VerifyError};
use crate::identity::hostname::Hostname;
use crate::identity::time::UnixTime;

pub const MAX_CHAIN_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    Empty,
    ChainTooLong,
    SignatureFailed,
    NotYetValid,
    Expired,
    IssuerNotCa,
    NoKeyCertSign,
    PathLenExceeded,
    NotEndEntity,
    IssuerSubjectMismatch,
    NoServerAuth,
    LeafKeyUsageInvalid,
    HostnameMismatch,
    NameConstraintViolation,
    NoTrustAnchor,
    UnhandledCriticalExtension,
    DuplicateExtension,
    Verify(VerifyError),
    Parse,
}

impl From<VerifyError> for ChainError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}

impl From<CertError> for ChainError {
    fn from(_: CertError) -> Self {
        Self::Parse
    }
}

#[derive(Debug, Clone)]
pub struct TrustAnchor<'a> {
    pub subject_der: &'a [u8],
    pub spki: SubjectPublicKeyInfo<'a>,
}

impl<'a> TrustAnchor<'a> {
    pub fn from_cert(cert: &'a Cert<'a>) -> Self {
        Self {
            subject_der: cert.subject_der,
            spki: cert.spki,
        }
    }
}

/// Every extension a chain check needs, parsed in one O(exts) pass that also
/// rejects duplicate and unhandled-critical extensions.
struct ParsedExt<'a> {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    eku_der: Option<&'a [u8]>,
    name_constraints_der: Option<&'a [u8]>,
    san_der: Option<&'a [u8]>,
}

impl<'a> ParsedExt<'a> {
    fn parse(cert: &Cert<'a>) -> Result<Self, ChainError> {
        let exts = cert.extensions_der.unwrap_or(&[]);
        let mut seen = ArrayVec::<&[u8], 64>::new();
        let mut basic_constraints = None;
        let mut key_usage = None;
        let mut eku_der = None;
        let mut name_constraints_der = None;
        let mut san_der = None;
        for ext in ExtensionIter::new(exts) {
            let ext = ext?;
            if seen.contains(&ext.oid) {
                return Err(ChainError::DuplicateExtension);
            }
            seen.try_push(ext.oid).map_err(|_| ChainError::Parse)?;
            if ext.critical && !ExtensionEntry::is_handled(ext.oid) {
                return Err(ChainError::UnhandledCriticalExtension);
            }
            if ext.oid == OID_EXT_BASIC_CONSTRAINTS {
                basic_constraints = Some(BasicConstraints::parse(ext.value)?);
            } else if ext.oid == OID_EXT_KEY_USAGE {
                key_usage = Some(KeyUsage::parse(ext.value)?);
            } else if ext.oid == OID_EXT_EXTENDED_KEY_USAGE {
                KeyUsage::parse_extended(ext.value)?;
                eku_der = Some(ext.value);
            } else if ext.oid == OID_EXT_NAME_CONSTRAINTS {
                NameConstraints::parse(ext.value)?;
                name_constraints_der = Some(ext.value);
            } else if ext.oid == OID_EXT_SAN {
                GeneralName::parse_alt_names(ext.value)?;
                san_der = Some(ext.value);
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
}

pub struct Chain<'a, 'der> {
    certs: &'a [Cert<'der>],
}

impl<'a, 'der> Chain<'a, 'der> {
    pub fn new(certs: &'a [Cert<'der>]) -> Self {
        Self { certs }
    }

    pub fn validate(
        &self,
        trust_anchors: &[TrustAnchor<'_>],
        now: UnixTime,
        hostname_dns_id: &[u8],
    ) -> Result<(), ChainError> {
        self.validate_with_anchor_verifier(now, hostname_dns_id, |subject| {
            Ok(Self::verifies_against_anchor(subject, trust_anchors))
        })
    }

    pub(crate) fn validate_with_anchor_verifier(
        &self,
        now: UnixTime,
        hostname_dns_id: &[u8],
        mut verifies_against_anchor: impl FnMut(&Cert<'der>) -> Result<bool, ChainError>,
    ) -> Result<(), ChainError> {
        let chain = self.certs;
        if chain.is_empty() {
            return Err(ChainError::Empty);
        }
        if chain.len() > MAX_CHAIN_LEN {
            return Err(ChainError::ChainTooLong);
        }

        let mut parsed = ArrayVec::<ParsedExt<'_>, MAX_CHAIN_LEN>::new();
        for cert in chain {
            parsed
                .try_push(ParsedExt::parse(cert)?)
                .map_err(|_| ChainError::ChainTooLong)?;
        }
        for c in chain {
            Self::check_validity(c, now)?;
        }

        Self::check_end_entity(&parsed[0])?;
        Self::check_server_auth(&parsed[0])?;
        Self::check_hostname(&parsed[0], hostname_dns_id)?;

        let order = Self::order_chain(chain);
        let all_linked = order.len() == chain.len();

        for (pos, &idx) in order.iter().enumerate() {
            let subject = &chain[idx];
            if verifies_against_anchor(subject)? {
                return Ok(());
            }
            if pos + 1 >= order.len() {
                return Err(if all_linked {
                    ChainError::NoTrustAnchor
                } else {
                    ChainError::IssuerSubjectMismatch
                });
            }
            let issuer = &chain[order[pos + 1]];
            let issuer_ext = &parsed[order[pos + 1]];
            if subject.issuer_der != issuer.subject_der {
                return Err(ChainError::IssuerSubjectMismatch);
            }
            Self::check_issuer_is_ca(issuer_ext)?;
            Self::check_ca_eku(issuer_ext)?;
            Self::check_path_len(issuer_ext, pos)?;
            if issuer_ext.name_constraints_der.is_some() {
                Self::check_name_constraints(issuer_ext, &parsed, &order[..=pos])?;
            }
            subject.verify_signature(&issuer.spki)?;
        }
        Err(ChainError::NoTrustAnchor)
    }

    /// Leaf→up ordering by issuer/subject linkage (RFC 8446 §4.4.2 allows
    /// shuffled chains). A signature check breaks ties only when several
    /// candidates share the issuer DN (cross-signing).
    fn order_chain(chain: &[Cert<'_>]) -> ArrayVec<usize, MAX_CHAIN_LEN> {
        let mut used = [false; MAX_CHAIN_LEN];
        let mut path = ArrayVec::new();
        let mut current_index = 0;
        used[0] = true;
        path.push(0);
        loop {
            let current = &chain[current_index];
            let mut first = None;
            let mut verifies = None;
            for (index, candidate) in chain.iter().enumerate() {
                if used[index] || candidate.subject_der != current.issuer_der {
                    continue;
                }
                first.get_or_insert(index);
                if verifies.is_none() && current.verify_signature(&candidate.spki).is_ok() {
                    verifies = Some(index);
                }
            }
            let chosen = match verifies.or(first) {
                Some(index) => index,
                None => break,
            };
            used[chosen] = true;
            path.push(chosen);
            current_index = chosen;
        }
        path
    }

    /// EKU chaining: an intermediate's EKU, if present, must permit serverAuth
    /// or anyExtendedKeyUsage.
    fn check_ca_eku(ext: &ParsedExt<'_>) -> Result<(), ChainError> {
        let Some(eku_der) = ext.eku_der else {
            return Ok(());
        };
        let ekus = KeyUsage::parse_extended(eku_der)?;
        if ekus.contains(&OID_EKU_SERVER_AUTH) || ekus.contains(&OID_EKU_ANY) {
            Ok(())
        } else {
            Err(ChainError::NoServerAuth)
        }
    }

    fn verifies_against_anchor(subject: &Cert<'_>, anchors: &[TrustAnchor<'_>]) -> bool {
        anchors.iter().any(|a| {
            a.subject_der == subject.issuer_der && subject.verify_signature(&a.spki).is_ok()
        })
    }

    /// RFC 5280 §4.2.1.10: a CA's name constraints bind every subordinate SAN
    /// below it, not just the leaf.
    fn check_name_constraints(
        ext: &ParsedExt<'_>,
        parsed: &[ParsedExt<'_>],
        subordinate_indices: &[usize],
    ) -> Result<(), ChainError> {
        let Some(name_constraints_der) = ext.name_constraints_der else {
            return Ok(());
        };
        let nc = NameConstraints::parse(name_constraints_der)?;
        if nc.permitted.has_unsupported || nc.excluded.has_unsupported {
            return Err(ChainError::NameConstraintViolation);
        }
        for &index in subordinate_indices {
            let Some(san_der) = parsed[index].san_der else {
                continue;
            };
            for name in GeneralName::parse_alt_names(san_der)? {
                match name {
                    GeneralName::DnsName(d) => {
                        if nc.excluded.dns.iter().any(|ex| Self::dns_in_subtree(d, ex)) {
                            return Err(ChainError::NameConstraintViolation);
                        }
                        if !nc.permitted.dns.is_empty()
                            && !nc.permitted.dns.iter().any(|p| Self::dns_in_subtree(d, p))
                        {
                            return Err(ChainError::NameConstraintViolation);
                        }
                    }
                    GeneralName::IpAddress(p) => {
                        if nc.excluded.ip.iter().any(|ex| Self::ip_in_subtree(p, ex)) {
                            return Err(ChainError::NameConstraintViolation);
                        }
                        if !nc.permitted.ip.is_empty()
                            && !nc
                                .permitted
                                .ip
                                .iter()
                                .any(|net| Self::ip_in_subtree(p, net))
                        {
                            return Err(ChainError::NameConstraintViolation);
                        }
                    }
                    GeneralName::Other { .. } => {}
                }
            }
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

    fn ip_in_subtree(addr: &[u8], net: &[u8]) -> bool {
        if net.len() != addr.len() * 2 {
            return false;
        }
        let (network, mask) = net.split_at(addr.len());
        addr.iter()
            .zip(network)
            .zip(mask)
            .all(|((a, n), m)| (a & m) == (n & m))
    }

    fn check_validity(c: &Cert<'_>, now: UnixTime) -> Result<(), ChainError> {
        let nb = UnixTime::from_time_value(&c.validity.not_before)?;
        let na = UnixTime::from_time_value(&c.validity.not_after)?;
        if now < nb {
            return Err(ChainError::NotYetValid);
        }
        if now > na {
            return Err(ChainError::Expired);
        }
        Ok(())
    }

    fn check_end_entity(ext: &ParsedExt<'_>) -> Result<(), ChainError> {
        if let Some(bc) = ext.basic_constraints
            && bc.ca
        {
            return Err(ChainError::NotEndEntity);
        }
        if let Some(ku) = ext.key_usage
            && !ku.has(KeyUsage::DIGITAL_SIGNATURE)
        {
            return Err(ChainError::LeafKeyUsageInvalid);
        }
        Ok(())
    }

    fn check_server_auth(ext: &ParsedExt<'_>) -> Result<(), ChainError> {
        let Some(eku_der) = ext.eku_der else {
            return Ok(());
        };
        let ekus = KeyUsage::parse_extended(eku_der)?;
        if ekus.contains(&OID_EKU_SERVER_AUTH) {
            Ok(())
        } else {
            Err(ChainError::NoServerAuth)
        }
    }

    fn check_hostname(ext: &ParsedExt<'_>, host: &[u8]) -> Result<(), ChainError> {
        let Some(san_der) = ext.san_der else {
            return Err(ChainError::HostnameMismatch);
        };
        let names = GeneralName::parse_alt_names(san_der)?;
        match Hostname::new(host).parse_ip() {
            Some(target) => {
                if names.iter().any(|name| {
                    matches!(
                        name,
                        GeneralName::IpAddress(p)
                            if Hostname::new(&target).matches_ip(p)
                    )
                }) {
                    return Ok(());
                }
            }
            None => {
                if names.iter().any(|name| {
                    matches!(
                        name,
                        GeneralName::DnsName(d)
                            if Hostname::new(host).matches_dns(d)
                    )
                }) {
                    return Ok(());
                }
            }
        }
        Err(ChainError::HostnameMismatch)
    }

    fn check_issuer_is_ca(ext: &ParsedExt<'_>) -> Result<(), ChainError> {
        let bc = ext.basic_constraints.ok_or(ChainError::IssuerNotCa)?;
        if !bc.ca {
            return Err(ChainError::IssuerNotCa);
        }
        if let Some(ku) = ext.key_usage
            && !ku.has(KeyUsage::KEY_CERT_SIGN)
        {
            return Err(ChainError::NoKeyCertSign);
        }
        Ok(())
    }

    fn check_path_len(ext: &ParsedExt<'_>, subject_index: usize) -> Result<(), ChainError> {
        if let Some(bc) = ext.basic_constraints
            && let Some(max_following) = bc.path_len_constraint
            && subject_index as u64 > max_following
        {
            return Err(ChainError::PathLenExceeded);
        }
        Ok(())
    }

    fn ascii_case_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len()
            && a.iter()
                .zip(b)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }
}
