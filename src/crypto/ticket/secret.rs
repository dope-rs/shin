use crate::crypto::material;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::transport;
use alloc::rc;
use ring::aead;
use ring::rand;
use zeroize::Zeroize as _;

/// ```compile_fail
/// use shin::crypto::ticket::Secret;
/// fn assert_send<T: Send>() {}
/// assert_send::<Secret>();
/// ```
#[derive(Clone)]
pub struct Secret {
    /// Cached expansion shared by immutable per-connection key snapshots.
    aead_key: Result<rc::Rc<aead::LessSafeKey>, ticket::Error>,
    _thread: threadbound::ThreadBound,
}

struct Plaintext {
    psk: [u8; ticket::PSK_LEN],
    age_add: [u8; ticket::AGE_ADD_LEN],
    issued_at: [u8; ticket::ISSUED_AT_LEN],
    suite: u16,
    alpn: arrayvec::ArrayVec<u8, { ticket::MAX_ALPN_LEN }>,
    context: ticket::Context,
}

impl Secret {
    pub fn new(mut secret: [u8; 32]) -> Self {
        let aead_key = Self::derive_aead_key(&secret).map(rc::Rc::new);
        secret.zeroize();
        Self {
            aead_key,
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub fn encrypt(
        &self,
        psk: &[u8; ticket::PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: u16,
        alpn: &[u8],
        rng: &impl rand::SecureRandom,
    ) -> Result<ticket::Encrypted, ticket::Error> {
        let psk =
            material::ResumptionPsk::try_from_slice(psk).map_err(|_| ticket::Error::BadFormat)?;
        self.encrypt_claims(
            ticket::Claims {
                psk: &psk,
                age_add,
                issued_at_ms,
                suite,
                alpn,
                context: ticket::Context::new(transport::Mode::Tls, None, &[]),
            },
            rng,
        )
    }

    pub fn encrypt_claims(
        &self,
        claims: ticket::Claims<'_>,
        rng: &impl rand::SecureRandom,
    ) -> Result<ticket::Encrypted, ticket::Error> {
        let ticket::Claims {
            psk,
            age_add,
            issued_at_ms,
            suite,
            alpn,
            context,
        } = claims;
        if alpn.len() > ticket::MAX_ALPN_LEN {
            return Err(ticket::Error::BadFormat);
        }
        let key = self.aead_key()?;
        let mut nonce_bytes = [0u8; ticket::NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| ticket::Error::BadKey)?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = arrayvec::ArrayVec::<u8, { ticket::MAX_PLAINTEXT_LEN }>::new();
        buf.try_extend_from_slice(psk.as_slice())
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(&age_add.to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(&issued_at_ms.to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(&suite.to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        context.encode(&mut buf)?;
        buf.try_push(alpn.len() as u8)
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(alpn)
            .map_err(|_| ticket::Error::BadFormat)?;
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), buf.as_mut_slice())
            .map_err(|_| ticket::Error::BadAuth)?;

        let mut out = ticket::Encrypted::new();
        out.bytes
            .try_extend_from_slice(&nonce_bytes)
            .map_err(|_| ticket::Error::BadFormat)?;
        out.bytes
            .try_extend_from_slice(&buf)
            .map_err(|_| ticket::Error::BadFormat)?;
        out.bytes
            .try_extend_from_slice(tag.as_ref())
            .map_err(|_| ticket::Error::BadFormat)?;
        Ok(out)
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<ticket::Decrypted, ticket::Error> {
        if encrypted.len()
            < ticket::NONCE_LEN + ticket::LEGACY_FIXED_PLAINTEXT_LEN + ticket::TAG_LEN
        {
            return Err(ticket::Error::BadFormat);
        }
        if encrypted.len() > ticket::MAX_LEN {
            return Err(ticket::Error::BadFormat);
        }
        let key = self.aead_key()?;
        let mut nonce_bytes = [0u8; ticket::NONCE_LEN];
        nonce_bytes.copy_from_slice(&encrypted[..ticket::NONCE_LEN]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = arrayvec::ArrayVec::<u8, { ticket::MAX_CIPHERTEXT_LEN }>::new();
        buf.try_extend_from_slice(&encrypted[ticket::NONCE_LEN..])
            .map_err(|_| ticket::Error::BadFormat)?;
        let plain = key
            .open_in_place(nonce, aead::Aad::empty(), buf.as_mut_slice())
            .map_err(|_| ticket::Error::BadAuth)?;
        if plain.len() < ticket::LEGACY_FIXED_PLAINTEXT_LEN {
            return Err(ticket::Error::BadFormat);
        }
        let parsed = Self::parse_plaintext(plain);
        buf.as_mut_slice().zeroize();
        let Plaintext {
            psk,
            age_add,
            issued_at,
            suite,
            alpn,
            context,
        } = parsed?;
        Ok(ticket::Decrypted {
            psk: material::ResumptionPsk::new(psk),
            age_add: u32::from_be_bytes(age_add),
            issued_at_ms: u64::from_be_bytes(issued_at),
            suite,
            alpn,
            context,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    fn derive_aead_key(secret: &[u8; 32]) -> Result<aead::LessSafeKey, ticket::Error> {
        use crate::crypto::hash::Algorithm;
        use crate::crypto::kdf::Hkdf;
        use ring::aead::UnboundKey;
        let mut key_bytes = [0u8; 16];
        Hkdf::new(Algorithm::Sha256)
            .expand_label(secret, "ticket", &[], &mut key_bytes)
            .map_err(|_| ticket::Error::BadKey)?;
        let unbound = UnboundKey::new(&aead::AES_128_GCM, &key_bytes);
        key_bytes.zeroize();
        let unbound = unbound.map_err(|_| ticket::Error::BadKey)?;
        Ok(aead::LessSafeKey::new(unbound))
    }

    fn aead_key(&self) -> Result<&aead::LessSafeKey, ticket::Error> {
        self.aead_key.as_deref().map_err(|error| *error)
    }

    fn parse_plaintext(plain: &[u8]) -> Result<Plaintext, ticket::Error> {
        let age_add_off = ticket::PSK_LEN;
        let issued_at_off = age_add_off + ticket::AGE_ADD_LEN;
        let suite_off = issued_at_off + ticket::ISSUED_AT_LEN;
        let context_off = suite_off + ticket::SUITE_LEN;
        let context_len = ticket::Context::encoded_len(plain[context_off])?;
        let alpn_len_off = context_off + context_len;
        let fixed_plaintext_len = alpn_len_off + ticket::ALPN_LEN_LEN;
        if plain.len() < fixed_plaintext_len {
            return Err(ticket::Error::BadFormat);
        }
        let alpn_len = plain[alpn_len_off] as usize;
        if plain.len() != fixed_plaintext_len + alpn_len {
            return Err(ticket::Error::BadFormat);
        }
        let context = ticket::Context::decode(&plain[context_off..alpn_len_off])?;
        let alpn = arrayvec::ArrayVec::try_from(&plain[fixed_plaintext_len..])
            .map_err(|_| ticket::Error::BadFormat)?;
        let mut age_bytes = [0u8; ticket::AGE_ADD_LEN];
        age_bytes.copy_from_slice(&plain[age_add_off..issued_at_off]);
        let mut issued_bytes = [0u8; ticket::ISSUED_AT_LEN];
        issued_bytes.copy_from_slice(&plain[issued_at_off..suite_off]);
        let suite = u16::from_be_bytes([plain[suite_off], plain[suite_off + 1]]);
        let mut psk = [0u8; ticket::PSK_LEN];
        psk.copy_from_slice(&plain[..ticket::PSK_LEN]);
        Ok(Plaintext {
            psk,
            age_add: age_bytes,
            issued_at: issued_bytes,
            suite,
            alpn,
            context,
        })
    }
}
