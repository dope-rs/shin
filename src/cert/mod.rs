use crate::asn1::{DerError, Reader, Tag, Tlv};

mod ext;

pub use ext::{
    BasicConstraints, ExtensionEntry, ExtensionIter, GeneralName, KeyUsage, NameConstraints,
    OID_EKU_CLIENT_AUTH, OID_EKU_SERVER_AUTH, OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_EXTENDED_KEY_USAGE, OID_EXT_KEY_USAGE, OID_EXT_NAME_CONSTRAINTS, OID_EXT_SAN, Subtrees,
    is_handled_ext,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    Der(DerError),
    BadVersion,
    BadValidity,
    BadAlgorithm,
}

impl From<DerError> for CertError {
    fn from(e: DerError) -> Self {
        Self::Der(e)
    }
}

#[derive(Debug, Clone)]
pub struct Cert<'a> {
    pub tbs_der: &'a [u8],
    pub version: u8,
    pub serial: &'a [u8],
    pub signature_alg: AlgorithmIdentifier<'a>,
    pub issuer_der: &'a [u8],
    pub validity: Validity<'a>,
    pub subject_der: &'a [u8],
    pub spki: SubjectPublicKeyInfo<'a>,
    pub extensions_der: Option<&'a [u8]>,
    pub outer_signature_alg: AlgorithmIdentifier<'a>,
    pub signature: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: &'a [u8],
    pub parameters: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Validity<'a> {
    pub not_before: TimeValue<'a>,
    pub not_after: TimeValue<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct TimeValue<'a> {
    pub tag: Tag,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: &'a [u8],
    pub raw_der: &'a [u8],
}

impl<'a> SubjectPublicKeyInfo<'a> {
    pub fn parse_standalone(spki_der: &'a [u8]) -> Result<Self, CertError> {
        let mut r = Reader::new(spki_der);
        let inner = r.expect(Tag::SEQUENCE)?;
        r.finish()?;
        let mut sr = Reader::new(inner);
        let alg_inner = sr.expect(Tag::SEQUENCE)?;
        let mut ar = Reader::new(alg_inner);
        let oid = ar.expect(Tag::OID)?;
        let parameters = ar.bytes_remaining();
        let bit = sr.expect(Tag::BIT_STRING)?;
        let subject_public_key = Tlv::bit_string(bit)?;
        sr.finish()?;
        Ok(Self {
            algorithm: AlgorithmIdentifier { oid, parameters },
            subject_public_key,
            raw_der: spki_der,
        })
    }

    fn parse_inline(r: &mut Reader<'a>) -> Result<Self, CertError> {
        let raw_der = Self::peek_full_tlv(r)?;
        let inner = r.expect(Tag::SEQUENCE)?;
        let mut sr = Reader::new(inner);
        let algorithm = AlgorithmIdentifier::parse(&mut sr)?;
        let bit = sr.expect(Tag::BIT_STRING)?;
        let subject_public_key = Tlv::bit_string(bit)?;
        sr.finish()?;
        Ok(Self {
            algorithm,
            subject_public_key,
            raw_der,
        })
    }

    fn peek_full_tlv(r: &Reader<'a>) -> Result<&'a [u8], CertError> {
        let bytes = r.bytes_remaining();
        let (tlv, _) = Tlv::parse_one(bytes)?;
        let tlv_len =
            (tlv.contents.as_ptr() as usize - bytes.as_ptr() as usize) + tlv.contents.len();
        Ok(&bytes[..tlv_len])
    }
}

impl<'a> Cert<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Self, CertError> {
        let (outer, rest) = Tlv::parse_one(der)?;
        if outer.tag != Tag::SEQUENCE {
            return Err(CertError::Der(DerError::Mismatch));
        }
        if !rest.is_empty() {
            return Err(CertError::Der(DerError::Trailing));
        }

        let mut top = Reader::new(outer.contents);

        let start_ptr = outer.contents.as_ptr();
        let tbs_tlv = top.next()?;
        if tbs_tlv.tag != Tag::SEQUENCE {
            return Err(CertError::Der(DerError::Mismatch));
        }
        let after_ptr = top.bytes_remaining().as_ptr();
        let consumed = (after_ptr as usize) - (start_ptr as usize);
        let tbs_der = &outer.contents[..consumed];

        let (
            version,
            serial,
            signature_alg,
            issuer_der,
            validity,
            subject_der,
            spki,
            extensions_der,
        ) = Self::parse_tbs(tbs_tlv.contents)?;

        let outer_signature_alg = AlgorithmIdentifier::parse(&mut top)?;

        if signature_alg.oid != outer_signature_alg.oid
            || signature_alg.parameters != outer_signature_alg.parameters
        {
            return Err(CertError::BadAlgorithm);
        }

        let sig_tlv = top.next()?;
        if sig_tlv.tag != Tag::BIT_STRING {
            return Err(CertError::Der(DerError::Mismatch));
        }
        let signature = Tlv::bit_string(sig_tlv.contents)?;

        top.finish()?;

        Ok(Self {
            tbs_der,
            version,
            serial,
            signature_alg,
            issuer_der,
            validity,
            subject_der,
            spki,
            extensions_der,
            outer_signature_alg,
            signature,
        })
    }

    #[allow(clippy::type_complexity)]
    fn parse_tbs(
        tbs: &'a [u8],
    ) -> Result<
        (
            u8,
            &'a [u8],
            AlgorithmIdentifier<'a>,
            &'a [u8],
            Validity<'a>,
            &'a [u8],
            SubjectPublicKeyInfo<'a>,
            Option<&'a [u8]>,
        ),
        CertError,
    > {
        let mut r = Reader::new(tbs);

        let version = if let Some(ver_inner) = r.read_optional(Tag::context(0, true))? {
            let mut vr = Reader::new(ver_inner);
            let v = Tlv::integer_u64(vr.expect(Tag::INTEGER)?)?;
            vr.finish()?;
            if v > 2 {
                return Err(CertError::BadVersion);
            }
            if v == 0 {
                return Err(CertError::BadVersion);
            }
            v as u8 + 1
        } else {
            1
        };

        let serial = r.expect(Tag::INTEGER)?;
        let signature_alg = AlgorithmIdentifier::parse(&mut r)?;
        let issuer_der = r.expect(Tag::SEQUENCE)?;
        let validity = Validity::parse(r.expect(Tag::SEQUENCE)?)?;
        let subject_der = r.expect(Tag::SEQUENCE)?;
        let spki = SubjectPublicKeyInfo::parse_inline(&mut r)?;

        let issuer_uid = r.read_optional(Tag::context(1, false))?.is_some();
        let subject_uid = r.read_optional(Tag::context(2, false))?.is_some();

        let extensions_der = if let Some(ext_outer) = r.read_optional(Tag::context(3, true))? {
            let mut er = Reader::new(ext_outer);
            let ext_seq = er.expect(Tag::SEQUENCE)?;
            er.finish()?;
            Some(ext_seq)
        } else {
            None
        };

        if extensions_der.is_some() && version != 3 {
            return Err(CertError::BadVersion);
        }
        if (issuer_uid || subject_uid) && version < 2 {
            return Err(CertError::BadVersion);
        }

        r.finish()?;
        Ok((
            version,
            serial,
            signature_alg,
            issuer_der,
            validity,
            subject_der,
            spki,
            extensions_der,
        ))
    }
}

impl<'a> AlgorithmIdentifier<'a> {
    fn parse(r: &mut Reader<'a>) -> Result<Self, CertError> {
        let alg_inner = r.expect(Tag::SEQUENCE)?;
        let mut ar = Reader::new(alg_inner);
        let oid = ar.expect(Tag::OID)?;
        let parameters = ar.bytes_remaining();
        Ok(Self { oid, parameters })
    }
}

impl AlgorithmIdentifier<'_> {
    pub fn oid_eq(&self, expected: &[u8]) -> bool {
        self.oid == expected
    }
}

impl<'a> Validity<'a> {
    fn parse(inner: &'a [u8]) -> Result<Self, CertError> {
        let mut r = Reader::new(inner);
        let nb = r.next()?;
        if nb.tag != Tag::UTC_TIME && nb.tag != Tag::GENERALIZED_TIME {
            return Err(CertError::BadValidity);
        }
        let na = r.next()?;
        if na.tag != Tag::UTC_TIME && na.tag != Tag::GENERALIZED_TIME {
            return Err(CertError::BadValidity);
        }
        r.finish()?;
        Ok(Self {
            not_before: TimeValue {
                tag: nb.tag,
                bytes: nb.contents,
            },
            not_after: TimeValue {
                tag: na.tag,
                bytes: na.contents,
            },
        })
    }
}

pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
pub const OID_SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
pub const OID_SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
pub const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
pub const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

pub const OID_P256_CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const OID_P384_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedAlgorithm,
    AlgorithmMismatch,
    UnsupportedCurve,
    BadCurveParam,
    Failed,
}

impl Cert<'_> {
    pub fn verify_signature(
        &self,
        issuer_spki: &SubjectPublicKeyInfo<'_>,
    ) -> Result<(), VerifyError> {
        let sig_oid = self.signature_alg.oid;
        let pk_oid = issuer_spki.algorithm.oid;

        let alg: &dyn ring::signature::VerificationAlgorithm = match (sig_oid, pk_oid) {
            (s, p) if s == OID_SHA256_WITH_RSA && p == OID_RSA_ENCRYPTION => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA256
            }
            (s, p) if s == OID_SHA384_WITH_RSA && p == OID_RSA_ENCRYPTION => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA384
            }
            (s, p) if s == OID_SHA512_WITH_RSA && p == OID_RSA_ENCRYPTION => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA512
            }
            (s, p) if s == OID_ECDSA_SHA256 && p == OID_EC_PUBLIC_KEY => {
                Self::check_named_curve(issuer_spki, OID_P256_CURVE)?;
                &ring::signature::ECDSA_P256_SHA256_ASN1
            }
            (s, p) if s == OID_ECDSA_SHA384 && p == OID_EC_PUBLIC_KEY => {
                Self::check_named_curve(issuer_spki, OID_P384_CURVE)?;
                &ring::signature::ECDSA_P384_SHA384_ASN1
            }
            (s, p) if s == OID_ED25519 && p == OID_ED25519 => &ring::signature::ED25519,
            (s, p) if Self::known_sig(s) && Self::known_pk(p) => {
                return Err(VerifyError::AlgorithmMismatch);
            }
            _ => return Err(VerifyError::UnsupportedAlgorithm),
        };

        let key = ring::signature::UnparsedPublicKey::new(alg, issuer_spki.subject_public_key);
        key.verify(self.tbs_der, self.signature)
            .map_err(|_| VerifyError::Failed)
    }

    fn known_sig(oid: &[u8]) -> bool {
        matches!(
            oid,
            x if x == OID_SHA256_WITH_RSA
                || x == OID_SHA384_WITH_RSA
                || x == OID_SHA512_WITH_RSA
                || x == OID_ECDSA_SHA256
                || x == OID_ECDSA_SHA384
                || x == OID_ED25519
        )
    }

    fn known_pk(oid: &[u8]) -> bool {
        matches!(
            oid,
            x if x == OID_RSA_ENCRYPTION
                || x == OID_EC_PUBLIC_KEY
                || x == OID_ED25519
        )
    }

    fn check_named_curve(
        spki: &SubjectPublicKeyInfo<'_>,
        expected_curve: &[u8],
    ) -> Result<(), VerifyError> {
        let mut r = Reader::new(spki.algorithm.parameters);
        let oid = r.expect(Tag::OID).map_err(|_| VerifyError::BadCurveParam)?;
        if oid != expected_curve {
            return Err(VerifyError::UnsupportedCurve);
        }
        Ok(())
    }
}
