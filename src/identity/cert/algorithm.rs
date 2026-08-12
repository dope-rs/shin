use crate::identity::asn1;
use crate::identity::cert;

const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const DER_NULL: &[u8] = &[0x05, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mask {
    Mgf1(Option<Hash>),
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParameters {
    hash: Option<Hash>,
    mask: Mask,
    salt_length: u64,
}

impl PssParameters {
    pub fn hash(self) -> Option<Hash> {
        self.hash
    }

    pub fn mask_hash(self) -> Option<Hash> {
        match self.mask {
            Mask::Mgf1(hash) => hash,
            Mask::Unsupported => None,
        }
    }

    pub fn salt_length(self) -> u64 {
        self.salt_length
    }

    fn profile(self) -> Option<PssProfile> {
        let (Some(hash), Mask::Mgf1(Some(mask_hash))) = (self.hash, self.mask) else {
            return None;
        };
        if hash != mask_hash {
            return None;
        }
        match (hash, self.salt_length) {
            (Hash::Sha256, 32) => Some(PssProfile::Sha256),
            (Hash::Sha384, 48) => Some(PssProfile::Sha384),
            (Hash::Sha512, 64) => Some(PssProfile::Sha512),
            _ => None,
        }
    }

    fn permits(self, signature: Self) -> bool {
        self.hash == signature.hash
            && self.mask == signature.mask
            && signature.salt_length >= self.salt_length
    }

    fn parse(der: &[u8]) -> Result<Self, cert::Error> {
        let mut outer = asn1::Reader::new(der);
        let contents = outer.read_tagged(asn1::Tag::SEQUENCE)?;
        outer.finish()?;
        let mut fields = asn1::Reader::new(contents);

        let hash = match fields.read_optional(asn1::Tag::context(0, true))? {
            Some(explicit) => {
                let hash = parse_explicit_hash(explicit)?;
                if hash == Some(Hash::Sha1) {
                    return Err(cert::Error::BadAlgorithm);
                }
                hash
            }
            None => Some(Hash::Sha1),
        };
        let mask = match fields.read_optional(asn1::Tag::context(1, true))? {
            Some(explicit) => {
                let mask = parse_explicit_mask(explicit)?;
                if mask == Mask::Mgf1(Some(Hash::Sha1)) {
                    return Err(cert::Error::BadAlgorithm);
                }
                mask
            }
            None => Mask::Mgf1(Some(Hash::Sha1)),
        };
        let salt_length = match fields.read_optional(asn1::Tag::context(2, true))? {
            Some(explicit) => {
                let salt_length = parse_explicit_integer(explicit)?;
                if salt_length == 20 {
                    return Err(cert::Error::BadAlgorithm);
                }
                salt_length
            }
            None => 20,
        };
        if let Some(explicit) = fields.read_optional(asn1::Tag::context(3, true))? {
            parse_explicit_integer(explicit)?;
            return Err(cert::Error::BadAlgorithm);
        }
        fields.finish()?;
        Ok(Self {
            hash,
            mask,
            salt_length,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPss(PssParameters),
    EcdsaSha256,
    EcdsaSha384,
    Ed25519,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCurve {
    P256,
    P384,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    Rsa,
    RsaPss(Option<PssParameters>),
    Ec(NamedCurve),
    Ed25519,
    Unsupported,
}

#[derive(Clone, Copy)]
pub(super) enum VerificationProfile {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RawIdentifier<'a> {
    oid: asn1::Oid<'a>,
    parameters: &'a [u8],
}

impl<'a> RawIdentifier<'a> {
    pub(super) fn parse(reader: &mut asn1::Reader<'a>) -> Result<Self, cert::Error> {
        let contents = reader.read_tagged(asn1::Tag::SEQUENCE)?;
        let mut algorithm = asn1::Reader::new(contents);
        let oid = algorithm.read_oid()?;
        let parameters = algorithm.bytes_remaining();
        if !parameters.is_empty() {
            let (_, trailing) = asn1::Tlv::parse_one(parameters)?;
            if !trailing.is_empty() {
                return Err(cert::Error::BadAlgorithm);
            }
        }
        Ok(Self { oid, parameters })
    }

    fn parse_exact(der: &'a [u8]) -> Result<Self, cert::Error> {
        let mut reader = asn1::Reader::new(der);
        let algorithm = Self::parse(&mut reader)?;
        reader.finish()?;
        Ok(algorithm)
    }
}

impl Signature {
    pub(super) fn parse(raw: RawIdentifier<'_>) -> Result<Self, cert::Error> {
        match raw.oid.as_bytes() {
            cert::OID_SHA256_WITH_RSA => {
                require_absent_or_null(raw.parameters)?;
                Ok(Self::RsaPkcs1Sha256)
            }
            cert::OID_SHA384_WITH_RSA => {
                require_absent_or_null(raw.parameters)?;
                Ok(Self::RsaPkcs1Sha384)
            }
            cert::OID_SHA512_WITH_RSA => {
                require_absent_or_null(raw.parameters)?;
                Ok(Self::RsaPkcs1Sha512)
            }
            cert::OID_RSA_PSS => {
                if raw.parameters.is_empty() {
                    return Err(cert::Error::BadAlgorithm);
                }
                Ok(Self::RsaPss(PssParameters::parse(raw.parameters)?))
            }
            cert::OID_ECDSA_SHA256 => {
                require_absent(raw.parameters)?;
                Ok(Self::EcdsaSha256)
            }
            cert::OID_ECDSA_SHA384 => {
                require_absent(raw.parameters)?;
                Ok(Self::EcdsaSha384)
            }
            cert::OID_ED25519 => {
                require_absent(raw.parameters)?;
                Ok(Self::Ed25519)
            }
            _ => Ok(Self::Unsupported),
        }
    }

    pub(super) fn verification_profile(
        self,
        key: PublicKey,
    ) -> Result<VerificationProfile, cert::VerifyError> {
        match (self, key) {
            (Self::RsaPkcs1Sha256, PublicKey::Rsa) => Ok(VerificationProfile::RsaPkcs1Sha256),
            (Self::RsaPkcs1Sha384, PublicKey::Rsa) => Ok(VerificationProfile::RsaPkcs1Sha384),
            (Self::RsaPkcs1Sha512, PublicKey::Rsa) => Ok(VerificationProfile::RsaPkcs1Sha512),
            (Self::RsaPss(parameters), PublicKey::Rsa) => pss_profile(parameters),
            (Self::RsaPss(parameters), PublicKey::RsaPss(constraints)) => {
                let profile = pss_profile(parameters)?;
                if constraints.is_some_and(|constraints| !constraints.permits(parameters)) {
                    return Err(cert::VerifyError::AlgorithmMismatch);
                }
                Ok(profile)
            }
            (Self::EcdsaSha256, PublicKey::Ec(NamedCurve::P256)) => {
                Ok(VerificationProfile::EcdsaP256Sha256)
            }
            (Self::EcdsaSha384, PublicKey::Ec(NamedCurve::P384)) => {
                Ok(VerificationProfile::EcdsaP384Sha384)
            }
            (Self::EcdsaSha256 | Self::EcdsaSha384, PublicKey::Ec(_)) => {
                Err(cert::VerifyError::UnsupportedCurve)
            }
            (Self::Ed25519, PublicKey::Ed25519) => Ok(VerificationProfile::Ed25519),
            (Self::Unsupported, _) | (_, PublicKey::Unsupported) => {
                Err(cert::VerifyError::UnsupportedAlgorithm)
            }
            _ => Err(cert::VerifyError::AlgorithmMismatch),
        }
    }
}

impl PublicKey {
    pub(super) fn parse(raw: RawIdentifier<'_>) -> Result<Self, cert::Error> {
        match raw.oid.as_bytes() {
            cert::OID_RSA_ENCRYPTION => {
                if raw.parameters != DER_NULL {
                    return Err(cert::Error::BadAlgorithm);
                }
                Ok(Self::Rsa)
            }
            cert::OID_RSA_PSS => {
                let parameters = if raw.parameters.is_empty() {
                    None
                } else {
                    Some(PssParameters::parse(raw.parameters)?)
                };
                Ok(Self::RsaPss(parameters))
            }
            cert::OID_EC_PUBLIC_KEY => {
                if raw.parameters.is_empty() {
                    return Err(cert::Error::BadAlgorithm);
                }
                let mut parameters = asn1::Reader::new(raw.parameters);
                let curve = match parameters.read_oid()?.as_bytes() {
                    cert::OID_P256_CURVE => NamedCurve::P256,
                    cert::OID_P384_CURVE => NamedCurve::P384,
                    _ => NamedCurve::Unsupported,
                };
                parameters.finish()?;
                Ok(Self::Ec(curve))
            }
            cert::OID_ED25519 => {
                require_absent(raw.parameters)?;
                Ok(Self::Ed25519)
            }
            _ => Ok(Self::Unsupported),
        }
    }
}

fn pss_profile(parameters: PssParameters) -> Result<VerificationProfile, cert::VerifyError> {
    match parameters.profile() {
        Some(PssProfile::Sha256) => Ok(VerificationProfile::RsaPssSha256),
        Some(PssProfile::Sha384) => Ok(VerificationProfile::RsaPssSha384),
        Some(PssProfile::Sha512) => Ok(VerificationProfile::RsaPssSha512),
        None => Err(cert::VerifyError::UnsupportedAlgorithm),
    }
}

#[derive(Clone, Copy)]
enum PssProfile {
    Sha256,
    Sha384,
    Sha512,
}

fn parse_explicit_hash(explicit: &[u8]) -> Result<Option<Hash>, cert::Error> {
    let mut reader = asn1::Reader::new(explicit);
    let raw = RawIdentifier::parse(&mut reader)?;
    reader.finish()?;
    parse_hash(raw)
}

fn parse_explicit_mask(explicit: &[u8]) -> Result<Mask, cert::Error> {
    let mut reader = asn1::Reader::new(explicit);
    let raw = RawIdentifier::parse(&mut reader)?;
    reader.finish()?;
    if !raw.oid.is(OID_MGF1) {
        return Ok(Mask::Unsupported);
    }
    if raw.parameters.is_empty() {
        return Err(cert::Error::BadAlgorithm);
    }
    Ok(Mask::Mgf1(parse_hash(RawIdentifier::parse_exact(
        raw.parameters,
    )?)?))
}

fn parse_hash(raw: RawIdentifier<'_>) -> Result<Option<Hash>, cert::Error> {
    let hash = match raw.oid.as_bytes() {
        OID_SHA1 => Hash::Sha1,
        OID_SHA256 => Hash::Sha256,
        OID_SHA384 => Hash::Sha384,
        OID_SHA512 => Hash::Sha512,
        _ => return Ok(None),
    };
    require_absent_or_null(raw.parameters)?;
    Ok(Some(hash))
}

fn parse_explicit_integer(explicit: &[u8]) -> Result<u64, cert::Error> {
    let mut reader = asn1::Reader::new(explicit);
    let value = reader.read_uint()?.to_u64()?;
    reader.finish()?;
    Ok(value)
}

fn require_absent(parameters: &[u8]) -> Result<(), cert::Error> {
    if parameters.is_empty() {
        Ok(())
    } else {
        Err(cert::Error::BadAlgorithm)
    }
}

fn require_absent_or_null(parameters: &[u8]) -> Result<(), cert::Error> {
    if parameters.is_empty() || parameters == DER_NULL {
        Ok(())
    } else {
        Err(cert::Error::BadAlgorithm)
    }
}
