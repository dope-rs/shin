use crate::client::config;
use crate::identity::cert;
use crate::identity::chain;
use alloc::boxed;
use alloc::rc;
use alloc::vec;
use cert::algorithm;
use cert::dn;
use core::mem;
use core::ops;

/// Validated trust anchors shared by client endpoints.
/// Handshakes search an issuer-sorted index and verify only matching subjects.
#[derive(Clone)]
pub struct TrustStore {
    inner: rc::Rc<StoreInner>,
}

struct StoreInner {
    anchors: vec::Vec<PreparedTrustAnchor>,
}

struct PreparedTrustAnchor {
    subject_der: boxed::Box<[u8]>,
    subject_key: dn::NameKey,
    spki: PreparedSpki,
    constraints: Option<boxed::Box<chain::PreparedNameConstraints>>,
}

struct PreparedSpki {
    der: boxed::Box<[u8]>,
    algorithm: algorithm::PublicKey,
    subject_public_key: ops::Range<usize>,
}

const _: () = assert!(mem::size_of::<TrustStore>() == mem::size_of::<usize>());
const _: () = assert!(
    mem::size_of::<Option<boxed::Box<chain::PreparedNameConstraints>>>() == mem::size_of::<usize>()
);
const _: () = assert!(mem::size_of::<PreparedTrustAnchor>() <= 128);

impl TrustStore {
    pub fn new(
        anchors: impl IntoIterator<Item = config::OwnedTrustAnchor>,
    ) -> Result<Self, config::Error> {
        let anchors: vec::Vec<_> = anchors.into_iter().collect();
        if anchors.is_empty() {
            return Err(config::Error::MissingTrustAnchors);
        }
        if anchors.len() > config::MAX_TRUST_ANCHORS {
            return Err(config::Error::TooManyTrustAnchors {
                count: anchors.len(),
                maximum: config::MAX_TRUST_ANCHORS,
            });
        }

        let mut prepared = vec::Vec::with_capacity(anchors.len());
        for (index, anchor) in anchors.into_iter().enumerate() {
            prepared.push(
                PreparedTrustAnchor::new(anchor)
                    .map_err(|_| config::Error::MalformedTrustAnchor { index })?,
            );
        }
        prepared.sort_unstable_by(|left, right| {
            left.subject_key
                .cmp(&right.subject_key)
                .then_with(|| left.subject_der.cmp(&right.subject_der))
        });
        Ok(Self {
            inner: rc::Rc::new(StoreInner { anchors: prepared }),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.anchors.is_empty()
    }

    pub(crate) fn verify_subject<'store>(
        &'store self,
        subject: &chain::PathCert<'_>,
    ) -> Result<Option<chain::AnchorMatch<'store>>, chain::Error> {
        let issuer = subject.issuer;
        let issuer_key = subject.issuer_key;
        let anchors = &self.inner.anchors;
        let start = anchors.partition_point(|anchor| anchor.subject_key < issuer_key);
        for anchor in &anchors[start..] {
            if anchor.subject_key != issuer_key {
                break;
            }
            let anchor_name = dn::DistinguishedName::from_validated(anchor.subject_der.as_ref());
            if !anchor_name.equivalent(issuer) {
                continue;
            }
            if subject.signed.verify_signature(&anchor.spki.view()).is_ok() {
                return Ok(Some(chain::AnchorMatch {
                    constraints: anchor
                        .constraints
                        .as_deref()
                        .map(chain::AnchorMatchConstraints::Prepared),
                }));
            }
        }
        Ok(None)
    }
}

impl PreparedTrustAnchor {
    fn new(anchor: config::OwnedTrustAnchor) -> Result<Self, chain::Error> {
        let (_, subject_key) = dn::DistinguishedName::prepared(&anchor.subject_der)?;
        let constraints = anchor
            .name_constraints_der
            .map(chain::PreparedNameConstraints::parse)
            .transpose()?
            .map(boxed::Box::new);
        Ok(Self {
            subject_der: anchor.subject_der.into_boxed_slice(),
            subject_key,
            spki: PreparedSpki::new(anchor.spki_der)?,
            constraints,
        })
    }
}

impl PreparedSpki {
    fn new(der: vec::Vec<u8>) -> Result<Self, chain::Error> {
        let parsed = cert::SubjectPublicKeyInfo::parse_standalone(&der)?;
        let algorithm = parsed.algorithm;
        let subject_public_key = Self::range_within(&der, parsed.subject_public_key);
        Ok(Self {
            der: der.into_boxed_slice(),
            algorithm,
            subject_public_key,
        })
    }

    fn view(&self) -> cert::SubjectPublicKeyInfo<'_> {
        cert::SubjectPublicKeyInfo {
            algorithm: self.algorithm,
            subject_public_key: &self.der[self.subject_public_key.clone()],
            raw_der: &self.der,
        }
    }

    fn range_within(whole: &[u8], part: &[u8]) -> ops::Range<usize> {
        let start = (part.as_ptr() as usize) - (whole.as_ptr() as usize);
        start..start + part.len()
    }
}
