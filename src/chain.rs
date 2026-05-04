use alloc::vec::Vec;

use crate::cert::{
    BasicConstraints, Cert, ExtensionIter, GeneralName, KeyUsage, OID_EKU_SERVER_AUTH,
    OID_EXT_BASIC_CONSTRAINTS, OID_EXT_EXTENDED_KEY_USAGE, OID_EXT_KEY_USAGE, OID_EXT_SAN,
    SubjectPublicKeyInfo, VerifyError,
};
use crate::hostname::Hostname;
use crate::time::UnixTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    Empty,
    SignatureFailed,
    NotYetValid,
    Expired,
    IssuerNotCa,
    NoKeyCertSign,
    NotEndEntity,
    NoServerAuth,
    HostnameMismatch,
    NoTrustAnchor,
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

        for c in chain {
            Self::check_validity(c, now)?;
        }

        let leaf = &chain[0];
        Self::check_end_entity(leaf)?;
        Self::check_server_auth(leaf)?;
        Self::check_hostname(leaf, hostname_dns_id)?;

        for i in 0..chain.len() {
            let subject = &chain[i];
            if let Ok(anchor) = Self::find_anchor_for(subject, trust_anchors) {
                subject.verify_signature(&anchor.spki)?;
                return Ok(());
            }
            if i + 1 >= chain.len() {
                return Err(ChainError::NoTrustAnchor);
            }
            let issuer = &chain[i + 1];
            Self::check_issuer_is_ca(issuer)?;
            subject.verify_signature(&issuer.spki)?;
        }
        Err(ChainError::NoTrustAnchor)
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

    fn check_end_entity(c: &Cert<'_>) -> Result<(), ChainError> {
        let exts = c.extensions_der.unwrap_or(&[]);
        if let Some((_, val)) = ExtensionIter::find(exts, OID_EXT_BASIC_CONSTRAINTS)? {
            let bc = BasicConstraints::parse(val)?;
            if bc.ca {
                return Err(ChainError::NotEndEntity);
            }
        }
        Ok(())
    }

    fn check_server_auth(c: &Cert<'_>) -> Result<(), ChainError> {
        let exts = c.extensions_der.unwrap_or(&[]);
        let Some((_, val)) = ExtensionIter::find(exts, OID_EXT_EXTENDED_KEY_USAGE)? else {
            return Ok(());
        };
        let ekus = KeyUsage::parse_extended(val)?;
        if ekus.contains(&OID_EKU_SERVER_AUTH) {
            Ok(())
        } else {
            Err(ChainError::NoServerAuth)
        }
    }

    fn check_hostname(leaf: &Cert<'_>, host: &[u8]) -> Result<(), ChainError> {
        let exts = leaf.extensions_der.ok_or(ChainError::HostnameMismatch)?;
        let (_, san_val) =
            ExtensionIter::find(exts, OID_EXT_SAN)?.ok_or(ChainError::HostnameMismatch)?;
        let names = GeneralName::parse_alt_names(san_val)?;
        let lowered = Self::ascii_lower(host);
        let is_ip = Self::parse_ip(host).is_some();
        for n in &names {
            match n {
                crate::cert::GeneralName::DnsName(d) if !is_ip => {
                    let presented = Self::ascii_lower(d);
                    if Hostname::dns_matches(&presented, &lowered) {
                        return Ok(());
                    }
                }
                crate::cert::GeneralName::IpAddress(p) if is_ip => {
                    if let Some(target) = Self::parse_ip(host)
                        && Hostname::ip_matches(p, &target)
                    {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(ChainError::HostnameMismatch)
    }

    fn check_issuer_is_ca(issuer: &Cert<'_>) -> Result<(), ChainError> {
        let exts = issuer.extensions_der.unwrap_or(&[]);
        let bc_val = ExtensionIter::find(exts, OID_EXT_BASIC_CONSTRAINTS)?
            .ok_or(ChainError::IssuerNotCa)?
            .1;
        if !BasicConstraints::parse(bc_val)?.ca {
            return Err(ChainError::IssuerNotCa);
        }
        if let Some((_, ku_val)) = ExtensionIter::find(exts, OID_EXT_KEY_USAGE)? {
            let ku = KeyUsage::parse(ku_val)?;
            if !ku.has(KeyUsage::KEY_CERT_SIGN) {
                return Err(ChainError::NoKeyCertSign);
            }
        }
        Ok(())
    }

    fn find_anchor_for<'a>(
        top: &Cert<'_>,
        anchors: &'a [TrustAnchor<'_>],
    ) -> Result<&'a TrustAnchor<'a>, ChainError> {
        for a in anchors {
            if a.subject_der == top.issuer_der {
                return Ok(a);
            }
        }
        Err(ChainError::NoTrustAnchor)
    }

    fn ascii_lower(s: &[u8]) -> Vec<u8> {
        s.iter().map(|b| b.to_ascii_lowercase()).collect()
    }

    fn parse_ip(host: &[u8]) -> Option<Vec<u8>> {
        let s = core::str::from_utf8(host).ok()?;
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut out = Vec::with_capacity(4);
        for p in parts {
            let n: u8 = p.parse().ok()?;
            out.push(n);
        }
        Some(out)
    }
}
