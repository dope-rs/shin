use crate::crypto::material;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::transport;
use crate::wire::record;
use alloc::rc;
use core::mem;
use o3::collections::fixed::array;
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
    aead_key: rc::Rc<aead::LessSafeKey>,
    _thread: threadbound::ThreadBound,
}

pub(super) struct Opened<'a> {
    pub(super) psk: &'a [u8; ticket::PSK_LEN],
    pub(super) age_add: u32,
    pub(super) issued_at_ms: u64,
    pub(super) suite: record::CipherSuite,
    pub(super) alpn: &'a [u8],
    pub(super) context: ticket::Context,
}

impl Opened<'_> {
    pub(super) fn to_owned(&self) -> Result<ticket::Decrypted, ticket::Error> {
        Ok(ticket::Decrypted {
            psk: material::ResumptionPsk::new(*self.psk),
            age_add: self.age_add,
            issued_at_ms: self.issued_at_ms,
            suite: self.suite,
            alpn: array::CopyInline::try_from_slice(self.alpn)
                .map_err(|_| ticket::Error::BadFormat)?,
            context: self.context,
            _thread: threadbound::ThreadBound::NEW,
        })
    }
}

const _: () = assert!(mem::size_of::<Opened<'static>>() <= 104);

struct OpenBuffer {
    bytes: array::CopyInline<u8, { ticket::MAX_CIPHERTEXT_LEN }>,
}

impl OpenBuffer {
    fn new() -> Self {
        Self {
            bytes: array::CopyInline::new(),
        }
    }
}

impl Drop for OpenBuffer {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

impl Secret {
    pub fn new(mut secret: [u8; 32]) -> Result<Self, ticket::Error> {
        let aead_key = Self::derive_aead_key(&secret);
        secret.zeroize();
        Ok(Self {
            aead_key: rc::Rc::new(aead_key?),
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn encrypt(
        &self,
        psk: &[u8; ticket::PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: record::CipherSuite,
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
        let key = &self.aead_key;
        let mut nonce_bytes = [0u8; ticket::NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| ticket::Error::BadKey)?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = array::CopyInline::<u8, { ticket::MAX_PLAINTEXT_LEN }>::new();
        buf.try_extend_from_slice(psk.as_slice())
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(&age_add.to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(&issued_at_ms.to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        buf.try_extend_from_slice(&suite.wire_id().to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        context.encode(&mut buf)?;
        buf.push(alpn.len() as u8)
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
        self.decrypt_with(encrypted, &|opened| opened.to_owned())?
    }

    pub(super) fn decrypt_with<R>(
        &self,
        encrypted: &[u8],
        consume: &impl for<'a> Fn(Opened<'a>) -> R,
    ) -> Result<R, ticket::Error> {
        if encrypted.len()
            < ticket::NONCE_LEN + ticket::LEGACY_FIXED_PLAINTEXT_LEN + ticket::TAG_LEN
        {
            return Err(ticket::Error::BadFormat);
        }
        if encrypted.len() > ticket::MAX_LEN {
            return Err(ticket::Error::BadFormat);
        }
        let key = &self.aead_key;
        let mut nonce_bytes = [0u8; ticket::NONCE_LEN];
        nonce_bytes.copy_from_slice(&encrypted[..ticket::NONCE_LEN]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut buffer = OpenBuffer::new();
        buffer
            .bytes
            .try_extend_from_slice(&encrypted[ticket::NONCE_LEN..])
            .map_err(|_| ticket::Error::BadFormat)?;
        let plain = key
            .open_in_place(nonce, aead::Aad::empty(), buffer.bytes.as_mut_slice())
            .map_err(|_| ticket::Error::BadAuth)?;
        if plain.len() < ticket::LEGACY_FIXED_PLAINTEXT_LEN {
            return Err(ticket::Error::BadFormat);
        }
        Ok(consume(Self::parse_plaintext(plain)?))
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

    fn parse_plaintext(plain: &[u8]) -> Result<Opened<'_>, ticket::Error> {
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
        let age_add = u32::from_be_bytes(
            plain[age_add_off..issued_at_off]
                .try_into()
                .map_err(|_| ticket::Error::BadFormat)?,
        );
        let issued_at_ms = u64::from_be_bytes(
            plain[issued_at_off..suite_off]
                .try_into()
                .map_err(|_| ticket::Error::BadFormat)?,
        );
        let suite = record::CipherSuite::from_u16(u16::from_be_bytes([
            plain[suite_off],
            plain[suite_off + 1],
        ]))
        .ok_or(ticket::Error::BadFormat)?;
        Ok(Opened {
            psk: plain[..ticket::PSK_LEN]
                .try_into()
                .map_err(|_| ticket::Error::BadFormat)?,
            age_add,
            issued_at_ms,
            suite,
            alpn: &plain[fixed_plaintext_len..],
            context,
        })
    }
}
