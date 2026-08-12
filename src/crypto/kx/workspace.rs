use crate::crypto::kx;
use core::mem;
use o3::collections::fixed::array;
use ring::rand;

/// Allocation-free key ownership borrowing one hybrid workspace for its full connection lifetime.
#[doc(hidden)]
pub struct Workspace<'workspace> {
    workspace: &'workspace mut kx::HybridWorkspace,
}

impl<'workspace> Workspace<'workspace> {
    pub(crate) fn new(workspace: &'workspace mut kx::HybridWorkspace) -> Self {
        workspace.clear();
        Self { workspace }
    }
}

impl kx::Proof for Workspace<'_> {}

impl kx::Initiator for Workspace<'_> {
    type Share<'share>
        = array::CopyInline<u8, { kx::MAX_CLIENT_SHARE_LEN }>
    where
        Self: 'share;

    fn generate<'share, R: rand::SecureRandom>(
        &'share mut self,
        group: kx::KexGroup,
        rng: &R,
    ) -> Result<Self::Share<'share>, kx::Error> {
        use kx::WorkspaceMaterial;
        self.clear();
        match group {
            kx::KexGroup::X25519 => {
                let material = kx::generate_classical(group, rng)?;
                let client_share =
                    array::CopyInline::try_from_slice(material.client_share.as_slice())
                        .map_err(|_| kx::Error::Generate)?;
                self.workspace.material = WorkspaceMaterial::X25519(material);
                Ok(client_share)
            }
            kx::KexGroup::Secp256r1 => {
                let material = kx::generate_classical(group, rng)?;
                let client_share =
                    array::CopyInline::try_from_slice(material.client_share.as_slice())
                        .map_err(|_| kx::Error::Generate)?;
                self.workspace.material = WorkspaceMaterial::Secp256r1(material);
                Ok(client_share)
            }
            kx::KexGroup::X25519Mlkem768 => {
                let (private, client_share) = kx::generate_hybrid(rng)?;
                self.workspace.material = WorkspaceMaterial::Hybrid(private);
                Ok(client_share)
            }
        }
    }

    fn pending_group(&self) -> Option<kx::KexGroup> {
        use kx::WorkspaceMaterial;
        match self.workspace.material {
            WorkspaceMaterial::Empty => None,
            WorkspaceMaterial::X25519(_) => Some(kx::KexGroup::X25519),
            WorkspaceMaterial::Secp256r1(_) => Some(kx::KexGroup::Secp256r1),
            WorkspaceMaterial::Hybrid(_) => Some(kx::KexGroup::X25519Mlkem768),
        }
    }

    fn agree(&mut self, server_share: &[u8]) -> Result<kx::SharedSecret, kx::Error> {
        use kx::WorkspaceMaterial;
        match mem::replace(&mut self.workspace.material, WorkspaceMaterial::Empty) {
            WorkspaceMaterial::Empty => Err(kx::Error::Generate),
            WorkspaceMaterial::X25519(material) => {
                kx::agree_classical(kx::KexGroup::X25519, material, server_share)
            }
            WorkspaceMaterial::Secp256r1(material) => {
                kx::agree_classical(kx::KexGroup::Secp256r1, material, server_share)
            }
            WorkspaceMaterial::Hybrid(private) => kx::agree_hybrid(private, server_share),
        }
    }

    fn clear(&mut self) {
        self.workspace.clear();
    }
}

impl Drop for Workspace<'_> {
    fn drop(&mut self) {
        <Self as kx::Initiator>::clear(self);
    }
}
