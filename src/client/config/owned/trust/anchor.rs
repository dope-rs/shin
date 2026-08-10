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
    /// Derives an anchor while preserving certificate nameConstraints.
    pub fn from_cert_der(cert_der: &[u8]) -> Result<Self, chain::Error> {
        use crate::identity::cert::Cert;
        let cert = Cert::parse(cert_der)?;
        let anchor = chain::TrustAnchor::from_cert(&cert);
        Ok(Self {
            subject_der: cert.tbs.subject_der.to_vec(),
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
