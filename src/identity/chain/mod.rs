use crate::identity;
use crate::identity::cert::ext;

use crate::identity::cert;
use alloc::boxed;
use alloc::vec;
use cert::dn;
use core::{borrow, mem};
use ext::scope;
use o3::collections::fixed::array;
mod extensions;
mod search;

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
    fn from(error: cert::Error) -> Self {
        match error {
            cert::Error::DuplicateExtension => Self::DuplicateExtension,
            _ => Self::Parse,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreparedNameConstraints {
    der: boxed::Box<[u8]>,
    spans: boxed::Box<[Span]>,
    ends: [u8; 4],
    has_unsupported: bool,
}

const _: () = assert!(mem::size_of::<PreparedNameConstraints>() <= 64);

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
enum NameKind {
    Dns,
    Ip,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedValues<'a> {
    der: &'a [u8],
    spans: &'a [Span],
}

impl PreparedNameConstraints {
    pub(crate) fn parse(der: vec::Vec<u8>) -> Result<Self, Error> {
        let parsed = scope::NameConstraints::parse(&der)?;
        let has_unsupported =
            parsed.permitted.has_unsupported() || parsed.excluded.has_unsupported();
        let capacity = usize::from(parsed.permitted.count) + usize::from(parsed.excluded.count);
        let mut spans = vec::Vec::with_capacity(capacity);
        let permitted_dns = Self::append(&der, parsed.permitted, NameKind::Dns, &mut spans)?;
        let permitted_ip = Self::append(&der, parsed.permitted, NameKind::Ip, &mut spans)?;
        let excluded_dns = Self::append(&der, parsed.excluded, NameKind::Dns, &mut spans)?;
        let excluded_ip = Self::append(&der, parsed.excluded, NameKind::Ip, &mut spans)?;
        Ok(Self {
            der: der.into_boxed_slice(),
            spans: spans.into_boxed_slice(),
            ends: [permitted_dns, permitted_ip, excluded_dns, excluded_ip],
            has_unsupported,
        })
    }

    pub(crate) fn has_unsupported(&self) -> bool {
        self.has_unsupported
    }

    pub(crate) fn permitted_dns(&self) -> PreparedValues<'_> {
        self.values(0, self.ends[0])
    }

    pub(crate) fn permitted_ip(&self) -> PreparedValues<'_> {
        self.values(self.ends[0], self.ends[1])
    }

    pub(crate) fn excluded_dns(&self) -> PreparedValues<'_> {
        self.values(self.ends[1], self.ends[2])
    }

    pub(crate) fn excluded_ip(&self) -> PreparedValues<'_> {
        self.values(self.ends[2], self.ends[3])
    }

    fn values(&self, start: u8, end: u8) -> PreparedValues<'_> {
        PreparedValues {
            der: &self.der,
            spans: &self.spans[usize::from(start)..usize::from(end)],
        }
    }

    fn append(
        der: &[u8],
        subtrees: scope::Subtrees<'_>,
        kind: NameKind,
        spans: &mut vec::Vec<Span>,
    ) -> Result<u8, Error> {
        for name in subtrees.iter() {
            let value = match (kind, name?) {
                (NameKind::Dns, scope::GeneralName::DnsName(value))
                | (NameKind::Ip, scope::GeneralName::IpAddress(value)) => value,
                _ => continue,
            };
            spans.push(Span::new(der, value)?);
        }
        u8::try_from(spans.len()).map_err(|_| Error::Parse)
    }
}

impl Span {
    fn new(whole: &[u8], part: &[u8]) -> Result<Self, Error> {
        let start = (part.as_ptr() as usize)
            .checked_sub(whole.as_ptr() as usize)
            .ok_or(Error::Parse)?;
        let end = start.checked_add(part.len()).ok_or(Error::Parse)?;
        if end > whole.len() {
            return Err(Error::Parse);
        }
        Ok(Self { start, end })
    }

    fn resolve(self, whole: &[u8]) -> Result<&[u8], Error> {
        whole.get(self.start..self.end).ok_or(Error::Parse)
    }
}

impl PreparedValues<'_> {
    pub(crate) fn is_empty(self) -> bool {
        self.spans.is_empty()
    }

    pub(crate) fn any(self, mut predicate: impl FnMut(&[u8]) -> bool) -> Result<bool, Error> {
        for span in self.spans {
            if predicate(span.resolve(self.der)?) {
                return Ok(true);
            }
        }
        Ok(false)
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
    pub(crate) constraints: Option<AnchorMatchConstraints<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AnchorMatchConstraints<'a> {
    Der(&'a [u8]),
    Prepared(&'a PreparedNameConstraints),
}

impl<'a> TrustAnchor<'a> {
    /// Derives trust information from a certificate and preserves its
    /// nameConstraints extension. Certificate validity and self-signature are
    /// intentionally not trust-anchor inputs.
    pub fn from_cert(cert: &cert::Cert<'a>) -> Self {
        Self {
            subject_der: cert.tbs.names.subject.as_der(),
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
        scope::NameConstraints::parse(name_constraints_der)?;
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
                scope::NameConstraints::parse(der)?;
                Ok(Some(der))
            }
            AnchorConstraints::CertificateExtensions(extensions_der) => {
                let mut found = None;
                for extension in ext::ExtensionIter::new(extensions_der) {
                    let extension = extension?;
                    if !extension.oid.is(ext::OID_NAME_CONSTRAINTS) {
                        continue;
                    }
                    scope::NameConstraints::parse(extension.value)?;
                    found = Some(extension.value);
                }
                Ok(found)
            }
        }
    }

    pub(crate) fn verify_subject(
        &self,
        subject: &PathCert<'_>,
    ) -> Result<Option<AnchorMatch<'a>>, Error> {
        let issuer = subject.issuer;
        if self.subject_der != issuer.as_der()
            && !dn::DistinguishedName::parse(self.subject_der)?.equivalent(issuer)
        {
            return Ok(None);
        }
        if subject.signed.verify_signature(&self.spki).is_err() {
            return Ok(None);
        }
        Ok(Some(AnchorMatch {
            constraints: self
                .name_constraints_der()?
                .map(AnchorMatchConstraints::Der),
        }))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PathCert<'der> {
    pub(crate) signed: cert::Signed<'der>,
    pub(crate) issuer: dn::DistinguishedName<'der>,
    pub(crate) subject: dn::DistinguishedName<'der>,
    pub(crate) issuer_key: dn::NameKey,
    validity: cert::Validity,
    pub(crate) spki: cert::SubjectPublicKeyInfo<'der>,
    profile: extensions::Profile<'der>,
}

const _: () = assert!(mem::size_of::<PathCert<'static>>() <= 216);

impl<'der> PathCert<'der> {
    fn new(cert: cert::Cert<'der>) -> Self {
        Self {
            signed: cert.signed(),
            issuer: cert.tbs.names.issuer,
            subject: cert.tbs.names.subject,
            issuer_key: cert.tbs.names.issuer_key,
            validity: cert.tbs.validity,
            spki: cert.tbs.spki,
            profile: extensions::Profile::raw(cert.tbs.extensions_der),
        }
    }

    fn prepare(&mut self, now: identity::UnixTime) -> Result<(), Error> {
        self.profile.prepare()?;
        if now < self.validity.not_before {
            return Err(Error::NotYetValid);
        }
        if now > self.validity.not_after {
            return Err(Error::Expired);
        }
        Ok(())
    }

    fn profile(&self) -> Result<&extensions::Profile<'der>, Error> {
        self.profile.resolve()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidatedLeaf<'der> {
    spki: cert::SubjectPublicKeyInfo<'der>,
}

impl<'der> ValidatedLeaf<'der> {
    pub(crate) fn spki(self) -> cert::SubjectPublicKeyInfo<'der> {
        self.spki
    }
}

pub struct Chain<'der> {
    certs: array::CopyInline<PathCert<'der>, MAX_LEN>,
    too_long: bool,
}

impl<'der> Chain<'der> {
    pub fn new<I, B>(certs: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: borrow::Borrow<cert::Cert<'der>>,
    {
        let mut chain = Self::empty();
        for certificate in certs {
            if chain.try_push(*certificate.borrow()).is_err() {
                chain.too_long = true;
                break;
            }
        }
        chain
    }

    pub(crate) fn empty() -> Self {
        Self {
            certs: array::CopyInline::new(),
            too_long: false,
        }
    }

    pub(crate) fn try_push(&mut self, certificate: cert::Cert<'der>) -> Result<(), Error> {
        self.certs
            .push(PathCert::new(certificate))
            .map_err(|_| Error::ChainTooLong)
    }

    pub fn validate(
        mut self,
        trust_anchors: &[TrustAnchor<'_>],
        now: identity::UnixTime,
        hostname_dns_id: &[u8],
    ) -> Result<(), Error> {
        self.validate_with_anchor_verifier(now, hostname_dns_id, |subject| {
            Self::verifies_against_anchor(subject, trust_anchors)
        })?;
        Ok(())
    }

    pub(crate) fn validate_with_anchor_verifier<'anchor>(
        &mut self,
        now: identity::UnixTime,
        hostname_dns_id: &[u8],
        mut verifies_against_anchor: impl FnMut(
            &PathCert<'der>,
        ) -> Result<Option<AnchorMatch<'anchor>>, Error>,
    ) -> Result<ValidatedLeaf<'der>, Error> {
        use crate::identity::chain::search::Search;

        if self.too_long {
            return Err(Error::ChainTooLong);
        }
        if self.certs.is_empty() {
            return Err(Error::Empty);
        }

        let verify_anchor = |subject: &PathCert<'der>, subordinates: search::Path<'_, 'der>| {
            let Some(anchor) = verifies_against_anchor(subject)? else {
                return Ok(false);
            };
            match anchor.constraints {
                Some(AnchorMatchConstraints::Der(der)) => {
                    extensions::Profile::check_name_constraints_der(der, subordinates)?;
                }
                Some(AnchorMatchConstraints::Prepared(constraints)) => {
                    extensions::Profile::check_prepared_name_constraints(
                        constraints,
                        subordinates,
                    )?;
                }
                None => {}
            }
            Ok(true)
        };
        Search::new(&mut self.certs, now, verify_anchor).run(hostname_dns_id)?;
        let leaf = self.certs.first().ok_or(Error::Empty)?;
        Ok(ValidatedLeaf { spki: leaf.spki })
    }

    fn verifies_against_anchor<'anchor>(
        subject: &PathCert<'_>,
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
