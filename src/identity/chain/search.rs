use crate::identity;
use crate::identity::chain::{self, extensions};
use core::{iter, mem, slice};
use o3::collections::fixed::array;

const SUBJECT_STATE_COUNT: usize = 1 << (chain::MAX_LEN - 2);
const STATE_COUNT: usize = 1 + (chain::MAX_LEN - 1) * SUBJECT_STATE_COUNT;
const STATE_WORD_COUNT: usize = STATE_COUNT.div_ceil(u64::BITS as usize);

#[derive(Clone, Copy)]
struct PreparedIndex(u8);

const _: () = assert!(mem::size_of::<PreparedIndex>() == 1);

impl PreparedIndex {
    fn new(index: usize) -> Result<Self, chain::Error> {
        if index >= chain::MAX_LEN {
            return Err(chain::Error::ChainTooLong);
        }
        Ok(Self(
            u8::try_from(index).map_err(|_| chain::Error::ChainTooLong)?,
        ))
    }

    fn resolve<'path, 'der>(
        self,
        certificates: &'path [chain::PathCert<'der>],
    ) -> Result<&'path extensions::Profile<'der>, chain::Error> {
        certificates
            .get(usize::from(self.0))
            .ok_or(chain::Error::Parse)?
            .profile()
    }
}

#[derive(Clone, Copy)]
struct Frame {
    subject: PreparedIndex,
    next_issuer: u8,
}

impl Frame {
    fn new(subject: PreparedIndex) -> Self {
        Self {
            subject,
            next_issuer: 0,
        }
    }
}

const _: () = assert!(mem::size_of::<Frame>() == 2);
const _: () = assert!(mem::size_of::<array::CopyInline<Frame, { chain::MAX_LEN }>>() <= 24);

/// A leaf-to-subject path borrowing validated profiles from the prepared
/// certificate chain. Only [`PreparedIndex`] values can enter its frames.
#[derive(Clone, Copy)]
pub(super) struct Path<'path, 'der> {
    certificates: &'path [chain::PathCert<'der>],
    frames: &'path [Frame],
}

impl<'path, 'der> Path<'path, 'der> {
    fn new(certificates: &'path [chain::PathCert<'der>], frames: &'path [Frame]) -> Self {
        Self {
            certificates,
            frames,
        }
    }

    pub(super) fn iter(self) -> PathIter<'path, 'der> {
        PathIter {
            certificates: self.certificates,
            frames: self.frames.iter(),
        }
    }
}

pub(super) struct PathIter<'path, 'der> {
    certificates: &'path [chain::PathCert<'der>],
    frames: slice::Iter<'path, Frame>,
}

impl<'path, 'der> Iterator for PathIter<'path, 'der> {
    type Item = Result<&'path extensions::Profile<'der>, chain::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.frames
            .next()
            .map(|frame| frame.subject.resolve(self.certificates))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.frames.size_hint()
    }
}

impl iter::ExactSizeIterator for PathIter<'_, '_> {}
impl iter::FusedIterator for PathIter<'_, '_> {}

struct Seen([u64; STATE_WORD_COUNT]);

impl Seen {
    fn new() -> Self {
        Self([0; STATE_WORD_COUNT])
    }

    /// Returns true exactly once for every reachable `(subject, used-set)`.
    /// The current non-leaf subject is removed from the used-set before
    /// indexing, so the table contains only the 2,305 valid states.
    fn admit(&mut self, subject: PreparedIndex, used: u16) -> Result<bool, chain::Error> {
        let state = if subject.0 == 0 {
            0
        } else {
            let subject = usize::from(subject.0) - 1;
            let subject_bit = 1usize << subject;
            let used = usize::from(used >> 1);
            if used & subject_bit == 0 {
                return Err(chain::Error::Parse);
            }
            let lower = used & (subject_bit - 1);
            let upper = (used >> (subject + 1)) << subject;
            1 + subject * SUBJECT_STATE_COUNT + lower + upper
        };
        let word = self
            .0
            .get_mut(state / u64::BITS as usize)
            .ok_or(chain::Error::Parse)?;
        let bit = 1u64 << (state % u64::BITS as usize);
        let fresh = *word & bit == 0;
        *word |= bit;
        Ok(fresh)
    }
}

const _: () = assert!(mem::size_of::<Seen>() == 296);

struct SignatureCache {
    checked: [u16; chain::MAX_LEN],
    valid: [u16; chain::MAX_LEN],
}

impl SignatureCache {
    fn new() -> Self {
        Self {
            checked: [0; chain::MAX_LEN],
            valid: [0; chain::MAX_LEN],
        }
    }

    fn get(&self, subject: usize, issuer: usize) -> Result<Option<bool>, chain::Error> {
        let bit = 1u16
            .checked_shl(u32::try_from(issuer).map_err(|_| chain::Error::ChainTooLong)?)
            .ok_or(chain::Error::ChainTooLong)?;
        let checked = *self.checked.get(subject).ok_or(chain::Error::Parse)?;
        let valid = *self.valid.get(subject).ok_or(chain::Error::Parse)?;
        Ok((checked & bit != 0).then_some(valid & bit != 0))
    }

    fn insert(&mut self, subject: usize, issuer: usize, valid: bool) -> Result<(), chain::Error> {
        let bit = 1u16
            .checked_shl(u32::try_from(issuer).map_err(|_| chain::Error::ChainTooLong)?)
            .ok_or(chain::Error::ChainTooLong)?;
        let checked = self.checked.get_mut(subject).ok_or(chain::Error::Parse)?;
        *checked |= bit;
        if valid {
            let valid = self.valid.get_mut(subject).ok_or(chain::Error::Parse)?;
            *valid |= bit;
        }
        Ok(())
    }
}

const _: () = assert!(mem::size_of::<SignatureCache>() == 40);

/// Memoized, allocation-free iterative search over bounded certificate paths.
pub(super) struct Search<'chain, 'der, VerifyAnchor> {
    certificates: &'chain mut [chain::PathCert<'der>],
    now: identity::UnixTime,
    verify_anchor: VerifyAnchor,
    seen: Seen,
    signatures: SignatureCache,
    failure: Option<chain::Error>,
}

impl<'chain, 'der, VerifyAnchor> Search<'chain, 'der, VerifyAnchor>
where
    VerifyAnchor:
        for<'path> FnMut(&chain::PathCert<'der>, Path<'path, 'der>) -> Result<bool, chain::Error>,
{
    pub(super) fn new(
        certificates: &'chain mut [chain::PathCert<'der>],
        now: identity::UnixTime,
        verify_anchor: VerifyAnchor,
    ) -> Self {
        Self {
            certificates,
            now,
            verify_anchor,
            seen: Seen::new(),
            signatures: SignatureCache::new(),
            failure: None,
        }
    }

    pub(super) fn run(mut self, hostname_dns_id: &[u8]) -> Result<(), chain::Error> {
        let leaf = self.prepare_candidate(0)?;
        leaf.resolve(self.certificates)?
            .check_leaf(hostname_dns_id)?;

        let mut frames = array::CopyInline::<Frame, { chain::MAX_LEN }>::new();
        frames
            .push(Frame::new(leaf))
            .map_err(|_| chain::Error::ChainTooLong)?;
        let mut used = 1u16;

        while let Some(frame) = frames.as_slice().last().copied() {
            let subject = frame.subject;
            if frame.next_issuer == 0 {
                let current = frames
                    .as_mut_slice()
                    .last_mut()
                    .ok_or(chain::Error::Parse)?;
                current.next_issuer = 1;
                if !self.seen.admit(subject, used)? {
                    Self::pop(&mut frames, &mut used)?;
                    continue;
                }
                if self.anchor_accepts(subject, &frames) {
                    return Ok(());
                }
            }

            let Some(issuer) = self.next_issuer(subject, used, &mut frames)? else {
                self.reject(if frames.len() == self.certificates.len() {
                    chain::Error::NoTrustAnchor
                } else {
                    chain::Error::IssuerSubjectMismatch
                });
                Self::pop(&mut frames, &mut used)?;
                continue;
            };

            let issuer_bit = 1u16
                .checked_shl(u32::from(issuer.0))
                .ok_or(chain::Error::ChainTooLong)?;
            frames
                .push(Frame::new(issuer))
                .map_err(|_| chain::Error::ChainTooLong)?;
            used |= issuer_bit;
        }

        Err(self.failure.unwrap_or(chain::Error::NoTrustAnchor))
    }

    fn next_issuer(
        &mut self,
        subject: PreparedIndex,
        used: u16,
        frames: &mut array::CopyInline<Frame, { chain::MAX_LEN }>,
    ) -> Result<Option<PreparedIndex>, chain::Error> {
        let subject_index = usize::from(subject.0);
        let subject_issuer = self
            .certificates
            .get(subject_index)
            .ok_or(chain::Error::Parse)?
            .issuer;

        loop {
            let issuer_index = {
                let frame = frames
                    .as_mut_slice()
                    .last_mut()
                    .ok_or(chain::Error::Parse)?;
                let index = usize::from(frame.next_issuer);
                if index >= self.certificates.len() {
                    return Ok(None);
                }
                frame.next_issuer = frame
                    .next_issuer
                    .checked_add(1)
                    .ok_or(chain::Error::ChainTooLong)?;
                index
            };
            let issuer_bit = 1u16
                .checked_shl(u32::try_from(issuer_index).map_err(|_| chain::Error::ChainTooLong)?)
                .ok_or(chain::Error::ChainTooLong)?;
            if used & issuer_bit != 0
                || !self
                    .certificates
                    .get(issuer_index)
                    .ok_or(chain::Error::Parse)?
                    .subject
                    .equivalent(subject_issuer)
            {
                continue;
            }

            let issuer = match self.prepare_candidate(issuer_index) {
                Ok(issuer) => issuer,
                Err(error) => {
                    self.reject(error);
                    continue;
                }
            };
            let checked = issuer.resolve(self.certificates).and_then(|profile| {
                profile.check_issuer(
                    Path::new(self.certificates, frames.as_slice()),
                    frames.len() - 1,
                )
            });
            if let Err(error) = checked {
                self.reject(error);
                continue;
            }
            if !self.signature_is_valid(subject_index, issuer_index)? {
                continue;
            }
            return Ok(Some(issuer));
        }
    }

    fn anchor_accepts(
        &mut self,
        subject: PreparedIndex,
        frames: &array::CopyInline<Frame, { chain::MAX_LEN }>,
    ) -> bool {
        let Some(subject) = self.certificates.get(usize::from(subject.0)) else {
            self.reject(chain::Error::Parse);
            return false;
        };
        match (self.verify_anchor)(subject, Path::new(self.certificates, frames.as_slice())) {
            Ok(accepted) => accepted,
            Err(error) => {
                self.reject(error);
                false
            }
        }
    }

    fn prepare_candidate(&mut self, candidate_index: usize) -> Result<PreparedIndex, chain::Error> {
        let prepared_index = PreparedIndex::new(candidate_index)?;
        self.certificates
            .get_mut(candidate_index)
            .ok_or(chain::Error::Parse)?
            .prepare(self.now)?;
        Ok(prepared_index)
    }

    fn signature_is_valid(
        &mut self,
        subject_index: usize,
        issuer_index: usize,
    ) -> Result<bool, chain::Error> {
        if let Some(valid) = self.signatures.get(subject_index, issuer_index)? {
            return Ok(valid);
        }
        let verification = {
            let subject = self
                .certificates
                .get(subject_index)
                .ok_or(chain::Error::Parse)?;
            let issuer = self
                .certificates
                .get(issuer_index)
                .ok_or(chain::Error::Parse)?;
            subject.signed.verify_signature(&issuer.spki)
        };
        match verification {
            Ok(()) => {
                self.signatures.insert(subject_index, issuer_index, true)?;
                Ok(true)
            }
            Err(error) => {
                self.signatures.insert(subject_index, issuer_index, false)?;
                self.reject(chain::Error::Verify(error));
                Ok(false)
            }
        }
    }

    fn pop(
        frames: &mut array::CopyInline<Frame, { chain::MAX_LEN }>,
        used: &mut u16,
    ) -> Result<(), chain::Error> {
        let frame = frames.pop().ok_or(chain::Error::Parse)?;
        let bit = 1u16
            .checked_shl(u32::from(frame.subject.0))
            .ok_or(chain::Error::ChainTooLong)?;
        *used &= !bit;
        Ok(())
    }

    fn reject(&mut self, error: chain::Error) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }
}
