use crate::identity;
use crate::identity::cert::ext;

use crate::identity::cert;
mod extensions;
mod path;

pub const MAX_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
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
    Verify(cert::VerifyError),
    Parse,
}

impl From<cert::VerifyError> for Error {
    fn from(e: cert::VerifyError) -> Self {
        Self::Verify(e)
    }
}

impl From<cert::Error> for Error {
    fn from(_: cert::Error) -> Self {
        Self::Parse
    }
}

#[derive(Debug, Clone)]
pub struct TrustAnchor<'a> {
    pub subject_der: &'a [u8],
    pub spki: cert::SubjectPublicKeyInfo<'a>,
    constraints: AnchorConstraints<'a>,
}

#[derive(Debug, Clone, Copy)]
enum AnchorConstraints<'a> {
    /// The caller supplied subject/SPKI trust information without constraints.
    Unconstrained,
    /// Constraints copied from an owned trust-anchor representation.
    NameConstraints(&'a [u8]),
    /// A certificate-derived anchor retains the source extensions so malformed
    /// or duplicate nameConstraints can never silently become unconstrained.
    CertificateExtensions(&'a [u8]),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AnchorMatch<'a> {
    pub(crate) name_constraints_der: Option<&'a [u8]>,
}

impl<'a> TrustAnchor<'a> {
    /// Derives trust information from a certificate and preserves its
    /// nameConstraints extension. Certificate validity and self-signature are
    /// intentionally not trust-anchor inputs.
    pub fn from_cert(cert: &'a cert::Cert<'a>) -> Self {
        Self {
            subject_der: cert.tbs.subject_der,
            spki: cert.tbs.spki,
            constraints: AnchorConstraints::CertificateExtensions(
                cert.tbs.extensions_der.unwrap_or(&[]),
            ),
        }
    }

    /// Constructs an explicitly unconstrained trust anchor from out-of-band
    /// trust information.
    pub fn unconstrained(subject_der: &'a [u8], spki: cert::SubjectPublicKeyInfo<'a>) -> Self {
        Self {
            subject_der,
            spki,
            constraints: AnchorConstraints::Unconstrained,
        }
    }

    /// Constructs a constrained trust anchor from out-of-band trust
    /// information. The extension value is the DER-encoded NameConstraints
    /// sequence inside extnValue, not the surrounding Extension wrapper.
    pub fn with_name_constraints(
        subject_der: &'a [u8],
        spki: cert::SubjectPublicKeyInfo<'a>,
        name_constraints_der: &'a [u8],
    ) -> Result<Self, Error> {
        ext::NameConstraints::parse(name_constraints_der)?;
        Ok(Self {
            subject_der,
            spki,
            constraints: AnchorConstraints::NameConstraints(name_constraints_der),
        })
    }

    pub(crate) fn name_constraints_der(&self) -> Result<Option<&'a [u8]>, Error> {
        match self.constraints {
            AnchorConstraints::Unconstrained => Ok(None),
            AnchorConstraints::NameConstraints(der) => {
                ext::NameConstraints::parse(der)?;
                Ok(Some(der))
            }
            AnchorConstraints::CertificateExtensions(extensions_der) => {
                let mut found = None;
                for extension in ext::ExtensionIter::new(extensions_der) {
                    let extension = extension?;
                    if extension.oid != ext::OID_NAME_CONSTRAINTS {
                        continue;
                    }
                    if found.is_some() {
                        return Err(Error::DuplicateExtension);
                    }
                    ext::NameConstraints::parse(extension.value)?;
                    found = Some(extension.value);
                }
                Ok(found)
            }
        }
    }

    pub(crate) fn verify_subject(
        &self,
        subject: &cert::Cert<'_>,
    ) -> Result<Option<AnchorMatch<'a>>, Error> {
        if self.subject_der != subject.tbs.issuer_der
            || subject.verify_signature(&self.spki).is_err()
        {
            return Ok(None);
        }
        Ok(Some(AnchorMatch {
            name_constraints_der: self.name_constraints_der()?,
        }))
    }
}

pub struct Chain<'a, 'der> {
    certs: &'a [cert::Cert<'der>],
}

impl<'a, 'der> Chain<'a, 'der> {
    pub fn new(certs: &'a [cert::Cert<'der>]) -> Self {
        Self { certs }
    }

    pub fn validate(
        &self,
        trust_anchors: &[TrustAnchor<'_>],
        now: identity::UnixTime,
        hostname_dns_id: &[u8],
    ) -> Result<(), Error> {
        self.validate_with_anchor_verifier(now, hostname_dns_id, |subject| {
            Self::verifies_against_anchor(subject, trust_anchors)
        })
    }

    pub(crate) fn validate_with_anchor_verifier<'anchor>(
        &self,
        now: identity::UnixTime,
        hostname_dns_id: &[u8],
        mut verifies_against_anchor: impl FnMut(
            &cert::Cert<'der>,
        ) -> Result<Option<AnchorMatch<'anchor>>, Error>,
    ) -> Result<(), Error> {
        use crate::identity::chain::extensions::Extensions;
        use crate::identity::chain::path::Path;

        let chain = self.certs;
        if chain.is_empty() {
            return Err(Error::Empty);
        }
        if chain.len() > MAX_LEN {
            return Err(Error::ChainTooLong);
        }

        let mut parsed = arrayvec::ArrayVec::<Extensions<'_>, MAX_LEN>::new();
        for cert in chain {
            parsed
                .try_push(Extensions::parse(cert)?)
                .map_err(|_| Error::ChainTooLong)?;
        }
        for certificate in chain {
            Extensions::check_validity(certificate, now)?;
        }

        parsed[0].check_leaf(hostname_dns_id)?;

        let order = Path::build(chain);
        let all_linked = order.len() == chain.len();

        for (pos, &idx) in order.indices().iter().enumerate() {
            let subject = &chain[idx];
            if let Some(anchor) = verifies_against_anchor(subject)? {
                if let Some(name_constraints_der) = anchor.name_constraints_der {
                    Extensions::check_name_constraints_der(
                        name_constraints_der,
                        &parsed,
                        &order.indices()[..=pos],
                    )?;
                }
                return Ok(());
            }
            if pos + 1 >= order.len() {
                return Err(if all_linked {
                    Error::NoTrustAnchor
                } else {
                    Error::IssuerSubjectMismatch
                });
            }
            let issuer = &chain[order.indices()[pos + 1]];
            let issuer_ext = &parsed[order.indices()[pos + 1]];
            if subject.tbs.issuer_der != issuer.tbs.subject_der {
                return Err(Error::IssuerSubjectMismatch);
            }
            issuer_ext.check_issuer(&parsed, &order.indices()[..=pos], pos)?;
            if order.requires_signature_verification(pos) {
                subject.verify_signature(&issuer.tbs.spki)?;
            }
        }
        Err(Error::NoTrustAnchor)
    }

    fn verifies_against_anchor<'anchor>(
        subject: &cert::Cert<'_>,
        anchors: &[TrustAnchor<'anchor>],
    ) -> Result<Option<AnchorMatch<'anchor>>, Error> {
        for anchor in anchors {
            if let Some(anchor_match) = anchor.verify_subject(subject)? {
                return Ok(Some(anchor_match));
            }
        }
        Ok(None)
    }
}
