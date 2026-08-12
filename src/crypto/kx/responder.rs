use crate::crypto::kx;
use ml_kem::{self, TryKeyInit as _};
use ring::{agreement, rand};

pub(super) enum Responder {
    Classical(kx::KexGroup),
    Hybrid(kx::KexGroup),
}

impl Responder {
    pub(super) fn new(group: kx::KexGroup) -> Self {
        match group {
            kx::KexGroup::X25519 | kx::KexGroup::Secp256r1 => Self::Classical(group),
            kx::KexGroup::X25519Mlkem768 => Self::Hybrid(group),
        }
    }

    pub(super) fn classical<'output, R: rand::SecureRandom>(
        self,
        client_share: &[u8],
        rng: &R,
        output: &'output mut [u8],
    ) -> Result<kx::ServerResponse<'output>, kx::Error> {
        let Self::Classical(group) = self else {
            return Err(kx::Error::InvalidOutput);
        };
        if output.len() != group.server_share_len() {
            return Err(kx::Error::InvalidOutput);
        }
        let ephemeral = agreement::EphemeralPrivateKey::generate(group.ecdh_algorithm(), rng)
            .map_err(|_| kx::Error::Generate)?;
        let public = ephemeral
            .compute_public_key()
            .map_err(|_| kx::Error::Generate)?;
        if public.as_ref().len() != output.len() {
            return Err(kx::Error::Generate);
        }
        let peer = agreement::UnparsedPublicKey::new(group.ecdh_algorithm(), client_share);
        let secret = agreement::agree_ephemeral(ephemeral, &peer, kx::SharedSecret::from_slice)
            .map_err(|_| kx::Error::InvalidPubkey)?;
        output.copy_from_slice(public.as_ref());
        Ok(kx::ServerResponse {
            share: output,
            secret,
        })
    }
    pub(super) fn hybrid<'output, R: rand::SecureRandom>(
        self,
        client_share: &[u8],
        rng: &R,
        output: &'output mut [u8],
    ) -> Result<kx::ServerResponse<'output>, kx::Error> {
        let Self::Hybrid(group) = self else {
            return Err(kx::Error::InvalidOutput);
        };
        if group != kx::KexGroup::X25519Mlkem768 {
            return Err(kx::Error::InvalidOutput);
        }
        if client_share.len() != kx::MLKEM768_EK_LEN + kx::X25519_LEN {
            return Err(kx::Error::InvalidPubkey);
        }
        if output.len() != kx::MLKEM768_CT_LEN + kx::X25519_LEN {
            return Err(kx::Error::InvalidOutput);
        }
        let (ek_bytes, x25519_client_pk) = client_share.split_at(kx::MLKEM768_EK_LEN);
        let encapsulation_key =
            ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(ek_bytes)
                .map_err(|_| kx::Error::InvalidPubkey)?;
        let mut randomness = [0u8; 32];
        rng.fill(&mut randomness).map_err(|_| kx::Error::Generate)?;
        let (ciphertext, mlkem_secret) =
            encapsulation_key.encapsulate_deterministic(&ml_kem::B32::from(randomness));

        let x25519 = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)
            .map_err(|_| kx::Error::Generate)?;
        let x25519_public = x25519
            .compute_public_key()
            .map_err(|_| kx::Error::Generate)?;
        if x25519_public.as_ref().len() != kx::X25519_LEN {
            return Err(kx::Error::Generate);
        }
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, x25519_client_pk);
        let secret = agreement::agree_ephemeral(x25519, &peer, |x25519_secret| {
            kx::SharedSecret::from_parts(mlkem_secret.as_slice(), x25519_secret)
        })
        .map_err(|_| kx::Error::InvalidPubkey)?;

        let (ciphertext_output, x25519_output) = output.split_at_mut(kx::MLKEM768_CT_LEN);
        ciphertext_output.copy_from_slice(ciphertext.as_slice());
        x25519_output.copy_from_slice(x25519_public.as_ref());
        Ok(kx::ServerResponse {
            share: output,
            secret,
        })
    }
}
