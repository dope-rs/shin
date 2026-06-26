use alloc::vec::Vec;

use crate::asn1::{DerError, Reader, Tag, Tlv};
use crate::cert::CertError;

pub const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
pub const OID_EXT_SAN: &[u8] = &[0x55, 0x1d, 0x11];
pub const OID_EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
pub const OID_EXT_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
pub const OID_EXT_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

pub const OID_EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
pub const OID_EKU_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

pub fn is_handled_ext(oid: &[u8]) -> bool {
    matches!(
        oid,
        OID_EXT_KEY_USAGE
            | OID_EXT_SAN
            | OID_EXT_BASIC_CONSTRAINTS
            | OID_EXT_NAME_CONSTRAINTS
            | OID_EXT_EXTENDED_KEY_USAGE
    )
}

#[derive(Debug, Clone, Copy)]
pub struct ExtensionEntry<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}

pub struct ExtensionIter<'a> {
    reader: Reader<'a>,
}

impl<'a> ExtensionIter<'a> {
    pub fn new(extensions_der: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(extensions_der),
        }
    }

    pub fn find(
        extensions_der: &'a [u8],
        oid: &[u8],
    ) -> Result<Option<(bool, &'a [u8])>, CertError> {
        for ext in Self::new(extensions_der) {
            let ext = ext?;
            if ext.oid == oid {
                return Ok(Some((ext.critical, ext.value)));
            }
        }
        Ok(None)
    }

    fn parse_entry(&mut self) -> Result<ExtensionEntry<'a>, CertError> {
        let inner = self.reader.expect(Tag::SEQUENCE)?;
        let mut r = Reader::new(inner);
        let oid = r.expect(Tag::OID)?;
        let critical = if r.peek_tag() == Some(Tag::BOOLEAN) {
            Tlv::boolean(r.expect(Tag::BOOLEAN)?).map_err(CertError::Der)?
        } else {
            false
        };
        let value = r.expect(Tag::OCTET_STRING)?;
        r.finish()?;
        Ok(ExtensionEntry {
            oid,
            critical,
            value,
        })
    }
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = Result<ExtensionEntry<'a>, CertError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some(self.parse_entry())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u64>,
}

impl BasicConstraints {
    pub fn parse(value: &[u8]) -> Result<Self, CertError> {
        let mut r = Reader::new(value);
        let inner = r.expect(Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = Reader::new(inner);
        let ca = if ir.peek_tag() == Some(Tag::BOOLEAN) {
            if !Tlv::boolean(ir.expect(Tag::BOOLEAN)?).map_err(CertError::Der)? {
                return Err(CertError::Der(DerError::BadBool));
            }
            true
        } else {
            false
        };
        let path_len_constraint = if ir.peek_tag() == Some(Tag::INTEGER) {
            if !ca {
                return Err(CertError::Der(DerError::Mismatch));
            }
            Some(Tlv::integer_u64(ir.expect(Tag::INTEGER)?)?)
        } else {
            None
        };
        ir.finish()?;
        Ok(Self {
            ca,
            path_len_constraint,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsage {
    bits: u16,
}

impl KeyUsage {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const NON_REPUDIATION: u16 = 1 << 1;
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    pub const DATA_ENCIPHERMENT: u16 = 1 << 3;
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
    pub const ENCIPHER_ONLY: u16 = 1 << 7;
    pub const DECIPHER_ONLY: u16 = 1 << 8;

    pub fn has(&self, mask: u16) -> bool {
        self.bits & mask == mask
    }

    pub fn raw_bits(&self) -> u16 {
        self.bits
    }

    pub fn parse(value: &[u8]) -> Result<Self, CertError> {
        let mut r = Reader::new(value);
        let bs = r.expect(Tag::BIT_STRING)?;
        r.finish()?;
        if bs.is_empty() {
            return Err(CertError::Der(DerError::BadBitString));
        }
        let unused = bs[0] as usize;
        if unused > 7 {
            return Err(CertError::Der(DerError::BadBitString));
        }
        let content = &bs[1..];
        if content.is_empty() {
            if unused != 0 {
                return Err(CertError::Der(DerError::BadBitString));
            }
            return Ok(Self { bits: 0 });
        }
        if content.len() > 2 {
            return Err(CertError::Der(DerError::BadBitString));
        }
        let last = *content.last().unwrap();
        if unused != 0 && last & ((1u16 << unused) - 1) as u8 != 0 {
            return Err(CertError::Der(DerError::BadBitString));
        }
        if last == 0 {
            return Err(CertError::Der(DerError::BadBitString));
        }
        let mut bits = 0u16;
        let b0 = content[0];
        for i in 0..8 {
            if (b0 >> (7 - i)) & 1 != 0 {
                bits |= 1 << i;
            }
        }
        if content.len() == 2 {
            let b1 = content[1];
            if (b1 >> 7) & 1 != 0 {
                bits |= 1 << 8;
            }
        }
        Ok(Self { bits })
    }

    pub fn parse_extended(value: &[u8]) -> Result<Vec<&[u8]>, CertError> {
        let mut r = Reader::new(value);
        let inner = r.expect(Tag::SEQUENCE)?;
        r.finish()?;
        let mut out = Vec::new();
        let mut ir = Reader::new(inner);
        while !ir.is_empty() {
            out.push(ir.expect(Tag::OID)?);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName<'a> {
    DnsName(&'a [u8]),
    IpAddress(&'a [u8]),
    Other { tag: u8, value: &'a [u8] },
}

impl<'a> GeneralName<'a> {
    pub fn parse_alt_names(value: &'a [u8]) -> Result<Vec<Self>, CertError> {
        let mut r = Reader::new(value);
        let inner = r.expect(Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = Reader::new(inner);
        let mut out = Vec::new();
        while !ir.is_empty() {
            let tlv = ir.next()?;
            let kind = tlv.tag.0 & 0x1f;
            out.push(match kind {
                2 => Self::DnsName(tlv.contents),
                7 => Self::IpAddress(tlv.contents),
                _ => Self::Other {
                    tag: tlv.tag.0,
                    value: tlv.contents,
                },
            });
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Subtrees<'a> {
    pub dns: Vec<&'a [u8]>,
    pub ip: Vec<&'a [u8]>,
}

#[derive(Debug, Clone, Default)]
pub struct NameConstraints<'a> {
    pub permitted: Subtrees<'a>,
    pub excluded: Subtrees<'a>,
}

impl<'a> NameConstraints<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, CertError> {
        let mut r = Reader::new(value);
        let inner = r.expect(Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = Reader::new(inner);
        let mut nc = Self::default();
        if ir.peek_tag() == Some(Tag::context(0, true)) {
            nc.permitted = Self::parse_subtrees(ir.next()?.contents)?;
        }
        if ir.peek_tag() == Some(Tag::context(1, true)) {
            nc.excluded = Self::parse_subtrees(ir.next()?.contents)?;
        }
        ir.finish()?;
        Ok(nc)
    }

    fn parse_subtrees(bytes: &'a [u8]) -> Result<Subtrees<'a>, CertError> {
        let mut r = Reader::new(bytes);
        let mut out = Subtrees::default();
        while !r.is_empty() {
            let subtree = r.expect(Tag::SEQUENCE)?;
            let base = Reader::new(subtree).next()?;
            if base.tag == Tag::context(2, false) {
                out.dns.push(base.contents);
            } else if base.tag == Tag::context(7, false) {
                out.ip.push(base.contents);
            }
        }
        Ok(out)
    }
}
