use crate::identity::chain;
use alloc::vec;

#[derive(Clone)]
pub struct OwnedTrustAnchor {
    pub subject_der: vec::Vec<u8>,
    pub spki_der: vec::Vec<u8>,
    /// DER NameConstraints value, or `None` for an unconstrained anchor.
    pub name_constraints_der: Option<vec::Vec<u8>>,
}

impl OwnedTrustAnchor {
    /// Copies X.509 subject, SPKI, and optional NameConstraints field values.
    /// SPKI and constraints exclude their surrounding SEQUENCE header.
    pub fn from_der_fields(
        subject_der: &[u8],
        spki_der: &[u8],
        name_constraints_der: Option<&[u8]>,
    ) -> Self {
        Self {
            subject_der: subject_der.to_vec(),
            spki_der: wrap_sequence(spki_der),
            name_constraints_der: name_constraints_der.map(wrap_sequence),
        }
    }

    /// Derives an anchor while preserving certificate nameConstraints.
    pub fn from_cert_der(cert_der: &[u8]) -> Result<Self, chain::Error> {
        use crate::identity::cert::Cert;
        let cert = Cert::parse(cert_der)?;
        let anchor = chain::TrustAnchor::from_cert(&cert);
        Ok(Self {
            subject_der: cert.tbs.names.subject.as_der().to_vec(),
            spki_der: cert.tbs.spki.raw_der.to_vec(),
            name_constraints_der: anchor.name_constraints_der()?.map(<[u8]>::to_vec),
        })
    }

    /// Constructs an unconstrained anchor from out-of-band trust data.
    pub fn unconstrained(subject_der: vec::Vec<u8>, spki_der: vec::Vec<u8>) -> Self {
        Self {
            subject_der,
            spki_der,
            name_constraints_der: None,
        }
    }

    pub(in crate::client) fn view(&self) -> Result<chain::TrustAnchor<'_>, chain::Error> {
        use crate::identity::cert::SubjectPublicKeyInfo;
        let spki = SubjectPublicKeyInfo::parse_standalone(&self.spki_der)?;
        match self.name_constraints_der.as_deref() {
            Some(constraints) => {
                chain::TrustAnchor::with_name_constraints(&self.subject_der, spki, constraints)
            }
            None => Ok(chain::TrustAnchor::unconstrained(&self.subject_der, spki)),
        }
    }
}

fn wrap_sequence(inner: &[u8]) -> vec::Vec<u8> {
    let bytes = inner.len().to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let length = &bytes[start..];
    let header_len = if inner.len() < 128 {
        2
    } else {
        2 + length.len()
    };
    let mut out = vec::Vec::with_capacity(header_len + inner.len());
    out.push(0x30);
    if inner.len() < 128 {
        out.push(inner.len() as u8);
    } else {
        out.push(0x80 | length.len() as u8);
        out.extend_from_slice(length);
    }
    out.extend_from_slice(inner);
    out
}
