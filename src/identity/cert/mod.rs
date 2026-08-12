use crate::identity;
use crate::identity::asn1;

use ring::signature;

pub mod algorithm;
pub mod dn;
pub mod ext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Der(asn1::DerError),
    BadVersion,
    BadValidity,
    BadAlgorithm,
    BadSerial,
    BadName,
    DuplicateExtension,
    TooManyEntries,
}

impl From<asn1::DerError> for Error {
    fn from(e: asn1::DerError) -> Self {
        Self::Der(e)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Cert<'a> {
    pub tbs_der: &'a [u8],
    pub tbs: Tbs<'a>,
    pub signature: Signature<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct Signature<'a> {
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
pub(crate) struct Signed<'a> {
    tbs_der: &'a [u8],
    algorithm: algorithm::Signature,
    signature: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub not_before: identity::UnixTime,
    pub not_after: identity::UnixTime,
}

#[derive(Debug, Clone, Copy)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: algorithm::PublicKey,
    pub subject_public_key: &'a [u8],
    pub raw_der: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Tbs<'a> {
    pub version: u8,
    pub serial: asn1::Uint<'a>,
    pub signature_alg: algorithm::Signature,
    pub names: Names<'a>,
    pub validity: Validity,
    pub spki: SubjectPublicKeyInfo<'a>,
    pub extensions_der: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy)]
pub struct Names<'a> {
    pub issuer: dn::DistinguishedName<'a>,
    pub subject: dn::DistinguishedName<'a>,
    pub(crate) issuer_key: dn::NameKey,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    pub fn parse_standalone(spki_der: &'a [u8]) -> Result<Self, Error> {
        let mut r = asn1::Reader::new(spki_der);
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let mut sr = asn1::Reader::new(inner);
        let algorithm = algorithm::PublicKey::parse(algorithm::RawIdentifier::parse(&mut sr)?)?;
        let subject_public_key = sr.read_bit_string()?.octets()?;
        sr.finish()?;
        Ok(Self {
            algorithm,
            subject_public_key,
            raw_der: spki_der,
        })
    }

    fn parse_inline(r: &mut asn1::Reader<'a>) -> Result<Self, Error> {
        let raw_der = Self::peek_full_tlv(r)?;
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        let mut sr = asn1::Reader::new(inner);
        let algorithm = algorithm::PublicKey::parse(algorithm::RawIdentifier::parse(&mut sr)?)?;
        let subject_public_key = sr.read_bit_string()?.octets()?;
        sr.finish()?;
        Ok(Self {
            algorithm,
            subject_public_key,
            raw_der,
        })
    }

    fn peek_full_tlv(r: &asn1::Reader<'a>) -> Result<&'a [u8], Error> {
        let bytes = r.bytes_remaining();
        let (tlv, _) = asn1::Tlv::parse_one(bytes)?;
        let tlv_len =
            (tlv.contents.as_ptr() as usize - bytes.as_ptr() as usize) + tlv.contents.len();
        Ok(&bytes[..tlv_len])
    }
}

impl<'a> Cert<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Self, Error> {
        let (outer, rest) = asn1::Tlv::parse_one(der)?;
        if outer.tag != asn1::Tag::SEQUENCE {
            return Err(Error::Der(asn1::DerError::Mismatch));
        }
        if !rest.is_empty() {
            return Err(Error::Der(asn1::DerError::Trailing));
        }

        let mut top = asn1::Reader::new(outer.contents);

        let start_ptr = outer.contents.as_ptr();
        let tbs_tlv = top.read_tlv()?;
        if tbs_tlv.tag != asn1::Tag::SEQUENCE {
            return Err(Error::Der(asn1::DerError::Mismatch));
        }
        let after_ptr = top.bytes_remaining().as_ptr();
        let consumed = (after_ptr as usize) - (start_ptr as usize);
        let tbs_der = &outer.contents[..consumed];

        let (tbs, inner_signature_alg) = Self::parse_tbs(tbs_tlv.contents)?;

        let outer_signature_alg = algorithm::RawIdentifier::parse(&mut top)?;

        if inner_signature_alg != outer_signature_alg {
            return Err(Error::BadAlgorithm);
        }

        let signature = top.read_bit_string()?.octets()?;

        top.finish()?;

        Ok(Self {
            tbs_der,
            tbs,
            signature: Signature { bytes: signature },
        })
    }

    fn parse_tbs(tbs: &'a [u8]) -> Result<(Tbs<'a>, algorithm::RawIdentifier<'a>), Error> {
        let mut r = asn1::Reader::new(tbs);

        let version = if let Some(ver_inner) = r.read_optional(asn1::Tag::context(0, true))? {
            let mut vr = asn1::Reader::new(ver_inner);
            let v = vr.read_uint()?.to_u64()?;
            vr.finish()?;
            if v > 2 {
                return Err(Error::BadVersion);
            }
            if v == 0 {
                return Err(Error::BadVersion);
            }
            v as u8 + 1
        } else {
            1
        };

        let serial = r.read_uint()?;
        if serial.is_zero() || serial.as_bytes().len() > 20 {
            return Err(Error::BadSerial);
        }
        let raw_signature_alg = algorithm::RawIdentifier::parse(&mut r)?;
        let signature_alg = algorithm::Signature::parse(raw_signature_alg)?;
        let issuer_der = r.read_tagged(asn1::Tag::SEQUENCE)?;
        let (issuer, issuer_key) = dn::DistinguishedName::prepared(issuer_der)?;
        let validity = Validity::parse(r.read_tagged(asn1::Tag::SEQUENCE)?)?;
        let subject_der = r.read_tagged(asn1::Tag::SEQUENCE)?;
        let subject = dn::DistinguishedName::parse(subject_der)?;
        let spki = SubjectPublicKeyInfo::parse_inline(&mut r)?;

        let issuer_uid = r
            .read_optional_bit_string(asn1::Tag::context(1, false))?
            .is_some();
        let subject_uid = r
            .read_optional_bit_string(asn1::Tag::context(2, false))?
            .is_some();

        let extensions_der =
            if let Some(ext_outer) = r.read_optional(asn1::Tag::context(3, true))? {
                let mut er = asn1::Reader::new(ext_outer);
                let ext_seq = er.read_tagged(asn1::Tag::SEQUENCE)?;
                er.finish()?;
                Some(ext_seq)
            } else {
                None
            };

        if extensions_der.is_some() && version != 3 {
            return Err(Error::BadVersion);
        }
        if (issuer_uid || subject_uid) && version < 2 {
            return Err(Error::BadVersion);
        }

        r.finish()?;
        Ok((
            Tbs {
                version,
                serial,
                signature_alg,
                names: Names {
                    issuer,
                    subject,
                    issuer_key,
                },
                validity,
                spki,
                extensions_der,
            },
            raw_signature_alg,
        ))
    }
}

impl Validity {
    fn parse(inner: &[u8]) -> Result<Self, Error> {
        let mut r = asn1::Reader::new(inner);
        let nb = r.read_tlv()?;
        let na = r.read_tlv()?;
        r.finish()?;
        let not_before = identity::UnixTime::from_x509(nb.tag, nb.contents)?;
        let not_after = identity::UnixTime::from_x509(na.tag, na.contents)?;
        if not_before > not_after {
            return Err(Error::BadValidity);
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }
}

pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
pub const OID_SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
pub const OID_SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
pub const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
pub const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
pub const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const OID_P256_CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const OID_P384_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedAlgorithm,
    AlgorithmMismatch,
    UnsupportedCurve,
    Failed,
}

impl Cert<'_> {
    pub fn verify_signature(
        &self,
        issuer_spki: &SubjectPublicKeyInfo<'_>,
    ) -> Result<(), VerifyError> {
        self.signed().verify_signature(issuer_spki)
    }
}

impl<'a> Cert<'a> {
    pub(crate) fn signed(&self) -> Signed<'a> {
        Signed {
            tbs_der: self.tbs_der,
            algorithm: self.tbs.signature_alg,
            signature: self.signature.bytes,
        }
    }
}

impl Signed<'_> {
    pub(crate) fn verify_signature(
        self,
        issuer_spki: &SubjectPublicKeyInfo<'_>,
    ) -> Result<(), VerifyError> {
        fn verify_with<A: signature::VerificationAlgorithm>(
            signed: Signed<'_>,
            issuer_spki: &SubjectPublicKeyInfo<'_>,
            algorithm: &'static A,
        ) -> Result<(), VerifyError> {
            signature::UnparsedPublicKey::new(algorithm, issuer_spki.subject_public_key)
                .verify(signed.tbs_der, signed.signature)
                .map_err(|_| VerifyError::Failed)
        }

        match self.algorithm.verification_profile(issuer_spki.algorithm)? {
            algorithm::VerificationProfile::RsaPkcs1Sha256 => {
                verify_with(self, issuer_spki, &signature::RSA_PKCS1_2048_8192_SHA256)
            }
            algorithm::VerificationProfile::RsaPkcs1Sha384 => {
                verify_with(self, issuer_spki, &signature::RSA_PKCS1_2048_8192_SHA384)
            }
            algorithm::VerificationProfile::RsaPkcs1Sha512 => {
                verify_with(self, issuer_spki, &signature::RSA_PKCS1_2048_8192_SHA512)
            }
            algorithm::VerificationProfile::RsaPssSha256 => {
                verify_with(self, issuer_spki, &signature::RSA_PSS_2048_8192_SHA256)
            }
            algorithm::VerificationProfile::RsaPssSha384 => {
                verify_with(self, issuer_spki, &signature::RSA_PSS_2048_8192_SHA384)
            }
            algorithm::VerificationProfile::RsaPssSha512 => {
                verify_with(self, issuer_spki, &signature::RSA_PSS_2048_8192_SHA512)
            }
            algorithm::VerificationProfile::EcdsaP256Sha256 => {
                verify_with(self, issuer_spki, &signature::ECDSA_P256_SHA256_ASN1)
            }
            algorithm::VerificationProfile::EcdsaP384Sha384 => {
                verify_with(self, issuer_spki, &signature::ECDSA_P384_SHA384_ASN1)
            }
            algorithm::VerificationProfile::Ed25519 => {
                verify_with(self, issuer_spki, &signature::ED25519)
            }
        }
    }
}
