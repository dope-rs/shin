use crate::crypto::kx;
use ring::rand;

/// Heap-compatible key ownership used by the ordinary client profile.
#[doc(hidden)]
pub struct Owned {
    pending: Option<kx::EphemeralKey>,
}

impl Owned {
    pub(crate) const fn new() -> Self {
        Self { pending: None }
    }
}

impl kx::Proof for Owned {}

impl kx::Initiator for Owned {
    type Share<'share> = &'share [u8];

    fn generate<'share, R: rand::SecureRandom>(
        &'share mut self,
        group: kx::KexGroup,
        rng: &R,
    ) -> Result<Self::Share<'share>, kx::Error> {
        self.pending = None;
        let pending = self.pending.insert(kx::EphemeralKey::generate(group, rng)?);
        Ok(pending.client_share())
    }

    fn pending_group(&self) -> Option<kx::KexGroup> {
        self.pending.as_ref().map(kx::EphemeralKey::group)
    }

    fn agree(&mut self, server_share: &[u8]) -> Result<kx::SharedSecret, kx::Error> {
        self.pending
            .take()
            .ok_or(kx::Error::Generate)?
            .agree(server_share)
    }

    fn clear(&mut self) {
        self.pending = None;
    }
}
