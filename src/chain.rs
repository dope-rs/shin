use alloc::vec::Vec;

use crate::cert::{
    BasicConstraints, Cert, ExtensionIter, GeneralName, KeyUsage, NameConstraints, OID_EKU_ANY,
    OID_EKU_SERVER_AUTH, OID_EXT_BASIC_CONSTRAINTS, OID_EXT_EXTENDED_KEY_USAGE, OID_EXT_KEY_USAGE,
    OID_EXT_NAME_CONSTRAINTS, OID_EXT_SAN, SubjectPublicKeyInfo, VerifyError, is_handled_ext,
};
use crate::hostname::Hostname;
use crate::time::UnixTime;

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

impl From<crate::cert::CertError> for ChainError {
    fn from(_: crate::cert::CertError) -> Self {
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
    eku: Option<Vec<&'a [u8]>>,
    name_constraints: Option<NameConstraints<'a>>,
    san: LeafSan<'a>,
}

impl<'a> ParsedExt<'a> {
    fn parse(cert: &Cert<'a>) -> Result<Self, ChainError> {
        let exts = cert.extensions_der.unwrap_or(&[]);
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut basic_constraints = None;
        let mut key_usage = None;
        let mut eku = None;
        let mut name_constraints = None;
        let mut dns = Vec::new();
        let mut ip = Vec::new();
        for ext in ExtensionIter::new(exts) {
            let ext = ext?;
            if seen.contains(&ext.oid) {
                return Err(ChainError::DuplicateExtension);
            }
            seen.push(ext.oid);
            if ext.critical && !is_handled_ext(ext.oid) {
                return Err(ChainError::UnhandledCriticalExtension);
            }
            if ext.oid == OID_EXT_BASIC_CONSTRAINTS {
                basic_constraints = Some(BasicConstraints::parse(ext.value)?);
            } else if ext.oid == OID_EXT_KEY_USAGE {
                key_usage = Some(KeyUsage::parse(ext.value)?);
            } else if ext.oid == OID_EXT_EXTENDED_KEY_USAGE {
                eku = Some(KeyUsage::parse_extended(ext.value)?);
            } else if ext.oid == OID_EXT_NAME_CONSTRAINTS {
                name_constraints = Some(NameConstraints::parse(ext.value)?);
            } else if ext.oid == OID_EXT_SAN {
                for n in GeneralName::parse_alt_names(ext.value)? {
                    match n {
                        GeneralName::DnsName(d) => dns.push(Chain::ascii_lower(d)),
                        GeneralName::IpAddress(p) => ip.push(p),
                        GeneralName::Other { .. } => {}
                    }
                }
            }
        }
        Ok(Self {
            basic_constraints,
            key_usage,
            eku,
            name_constraints,
            san: LeafSan { dns, ip },
        })
    }
}

#[derive(Clone)]
struct LeafSan<'a> {
    dns: Vec<Vec<u8>>,
    ip: Vec<&'a [u8]>,
}

pub struct Chain;

impl Chain {
    pub fn validate(
        chain: &[Cert<'_>],
        trust_anchors: &[TrustAnchor<'_>],
        now: UnixTime,
        hostname_dns_id: &[u8],
    ) -> Result<(), ChainError> {
        if chain.is_empty() {
            return Err(ChainError::Empty);
        }
        if chain.len() > MAX_CHAIN_LEN {
            return Err(ChainError::ChainTooLong);
        }

        let parsed: Vec<ParsedExt> = chain
            .iter()
            .map(ParsedExt::parse)
            .collect::<Result<_, _>>()?;
        for c in chain {
            Self::check_validity(c, now)?;
        }

        Self::check_end_entity(&parsed[0])?;
        Self::check_server_auth(&parsed[0])?;
        Self::check_hostname(&parsed[0].san, hostname_dns_id)?;

        let order = Self::order_chain(chain);
        let all_linked = order.len() == chain.len();

        for (pos, &idx) in order.iter().enumerate() {
            let subject = &chain[idx];
            if Self::verifies_against_anchor(subject, trust_anchors) {
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
            if issuer_ext.name_constraints.is_some() {
                let subordinate_sans: Vec<&LeafSan> =
                    order[..=pos].iter().map(|&i| &parsed[i].san).collect();
                Self::check_name_constraints(issuer_ext, &subordinate_sans)?;
            }
            subject.verify_signature(&issuer.spki)?;
        }
        Err(ChainError::NoTrustAnchor)
    }

    /// Leaf→up ordering by issuer/subject linkage (RFC 8446 §4.4.2 allows
    /// shuffled chains). A signature check breaks ties only when several
    /// candidates share the issuer DN (cross-signing).
    fn order_chain(chain: &[Cert<'_>]) -> Vec<usize> {
        let mut used = alloc::vec![false; chain.len()];
        let mut path = alloc::vec![0usize];
        used[0] = true;
        loop {
            let current = &chain[*path.last().unwrap()];
            let matches: Vec<usize> = chain
                .iter()
                .enumerate()
                .filter(|&(idx, cand)| !used[idx] && cand.subject_der == current.issuer_der)
                .map(|(idx, _)| idx)
                .collect();
            let chosen = match matches.as_slice() {
                [] => break,
                &[only] => only,
                many => many
                    .iter()
                    .copied()
                    .find(|&idx| current.verify_signature(&chain[idx].spki).is_ok())
                    .unwrap_or(many[0]),
            };
            used[chosen] = true;
            path.push(chosen);
        }
        path
    }

    /// EKU chaining: an intermediate's EKU, if present, must permit serverAuth
    /// or anyExtendedKeyUsage.
    fn check_ca_eku(ext: &ParsedExt<'_>) -> Result<(), ChainError> {
        let Some(ekus) = &ext.eku else {
            return Ok(());
        };
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
        subordinates: &[&LeafSan<'_>],
    ) -> Result<(), ChainError> {
        let Some(nc) = &ext.name_constraints else {
            return Ok(());
        };
        if nc.permitted.has_unsupported || nc.excluded.has_unsupported {
            return Err(ChainError::NameConstraintViolation);
        }
        let permitted_dns: Vec<Vec<u8>> = nc
            .permitted
            .dns
            .iter()
            .map(|p| Self::ascii_lower(p))
            .collect();
        let excluded_dns: Vec<Vec<u8>> = nc
            .excluded
            .dns
            .iter()
            .map(|p| Self::ascii_lower(p))
            .collect();

        for san in subordinates {
            for d in &san.dns {
                if excluded_dns.iter().any(|ex| Self::dns_in_subtree(d, ex)) {
                    return Err(ChainError::NameConstraintViolation);
                }
                if !permitted_dns.is_empty()
                    && !permitted_dns.iter().any(|p| Self::dns_in_subtree(d, p))
                {
                    return Err(ChainError::NameConstraintViolation);
                }
            }

            for p in &san.ip {
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
        if !subdomains_only && name == constraint {
            return true;
        }
        name.len() > constraint.len()
            && name[name.len() - constraint.len() - 1] == b'.'
            && &name[name.len() - constraint.len()..] == constraint
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
        let Some(ekus) = &ext.eku else {
            return Ok(());
        };
        if ekus.contains(&OID_EKU_SERVER_AUTH) {
            Ok(())
        } else {
            Err(ChainError::NoServerAuth)
        }
    }

    fn check_hostname(leaf_san: &LeafSan<'_>, host: &[u8]) -> Result<(), ChainError> {
        match Self::parse_ip(host) {
            Some(target) => {
                if leaf_san.ip.iter().any(|p| Hostname::ip_matches(p, &target)) {
                    return Ok(());
                }
            }
            None => {
                let lowered = Self::ascii_lower(host);
                if leaf_san
                    .dns
                    .iter()
                    .any(|d| Hostname::dns_matches(d, &lowered))
                {
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

    fn ascii_lower(s: &[u8]) -> Vec<u8> {
        s.iter().map(|b| b.to_ascii_lowercase()).collect()
    }

    fn parse_ip(host: &[u8]) -> Option<Vec<u8>> {
        let s = core::str::from_utf8(host).ok()?;
        if s.contains(':') {
            Self::parse_ipv6(s)
        } else {
            Self::parse_ipv4(s)
        }
    }

    fn parse_ipv4(s: &str) -> Option<Vec<u8>> {
        let mut parts = s.split('.');
        let mut out = Vec::with_capacity(4);
        for _ in 0..4 {
            let p = parts.next()?;
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            out.push(p.parse::<u8>().ok()?);
        }
        if parts.next().is_some() {
            return None;
        }
        Some(out)
    }

    // RFC 4291 IPv6: "::" compression and a trailing embedded IPv4. Returns 16 bytes.
    fn parse_ipv6(s: &str) -> Option<Vec<u8>> {
        let (head, tail, compressed) = match s.find("::") {
            Some(i) => {
                if s[i + 2..].contains("::") {
                    return None;
                }
                (&s[..i], &s[i + 2..], true)
            }
            None => (s, "", false),
        };

        let (head_bytes, head_groups) = Self::parse_v6_part(head)?;
        let (tail_bytes, tail_groups) = Self::parse_v6_part(tail)?;

        if compressed {
            let total = head_groups + tail_groups;
            if total >= 8 {
                return None;
            }
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(&head_bytes);
            out.resize(out.len() + (8 - total) * 2, 0);
            out.extend_from_slice(&tail_bytes);
            Some(out)
        } else if head_groups == 8 && tail.is_empty() {
            Some(head_bytes)
        } else {
            None
        }
    }

    // One "::"-delimited side -> (bytes, group count); an embedded IPv4 is 2 groups.
    fn parse_v6_part(part: &str) -> Option<(Vec<u8>, usize)> {
        if part.is_empty() {
            return Some((Vec::new(), 0));
        }
        let tokens: Vec<&str> = part.split(':').collect();
        let mut out = Vec::new();
        let mut groups = 0;
        for (idx, tok) in tokens.iter().enumerate() {
            if tok.contains('.') {
                if idx != tokens.len() - 1 {
                    return None;
                }
                out.extend_from_slice(&Self::parse_ipv4(tok)?);
                groups += 2;
            } else {
                if tok.is_empty() || tok.len() > 4 || !tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                out.extend_from_slice(&u16::from_str_radix(tok, 16).ok()?.to_be_bytes());
                groups += 1;
            }
        }
        Some((out, groups))
    }
}
