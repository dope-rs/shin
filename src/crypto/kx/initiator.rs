use crate::crypto::kx;
use ring::rand;

/// Internal client key-exchange ownership strategy exposed only as a hidden default parameter.
#[doc(hidden)]
pub trait Initiator: kx::Proof {
    type Share<'share>: AsRef<[u8]>
    where
        Self: 'share;

    fn generate<'share, R: rand::SecureRandom>(
        &'share mut self,
        group: kx::KexGroup,
        rng: &R,
    ) -> Result<Self::Share<'share>, kx::Error>;

    fn pending_group(&self) -> Option<kx::KexGroup>;
    fn agree(&mut self, server_share: &[u8]) -> Result<kx::SharedSecret, kx::Error>;
    fn clear(&mut self);
}
