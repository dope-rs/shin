use crate::identity::asn1;
use crate::identity::cert;

pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
pub const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
pub const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

pub const OID_EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
pub const OID_EKU_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
pub const OID_EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
pub const MAX_EXTENSION_VALUES: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct ExtensionEntry<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}

impl ExtensionEntry<'_> {
    pub fn is_handled(oid: &[u8]) -> bool {
        matches!(
            oid,
            OID_KEY_USAGE
                | OID_SUBJECT_ALT_NAME
                | OID_BASIC_CONSTRAINTS
                | OID_NAME_CONSTRAINTS
                | OID_EXTENDED_KEY_USAGE
        )
    }
}

pub struct ExtensionIter<'a> {
    reader: asn1::Reader<'a>,
}

impl<'a> ExtensionIter<'a> {
    pub fn new(extensions_der: &'a [u8]) -> Self {
        Self {
            reader: asn1::Reader::new(extensions_der),
        }
    }

    pub fn find(
        extensions_der: &'a [u8],
        oid: &[u8],
    ) -> Result<Option<(bool, &'a [u8])>, cert::Error> {
        for ext in Self::new(extensions_der) {
            let ext = ext?;
            if ext.oid == oid {
                return Ok(Some((ext.critical, ext.value)));
            }
        }
        Ok(None)
    }

    fn parse_entry(&mut self) -> Result<ExtensionEntry<'a>, cert::Error> {
        let inner = self.reader.read_tagged(asn1::Tag::SEQUENCE)?;
        let mut r = asn1::Reader::new(inner);
        let oid = r.read_tagged(asn1::Tag::OID)?;
        let critical = if r.peek_tag() == Some(asn1::Tag::BOOLEAN) {
            asn1::Tlv::boolean(r.read_tagged(asn1::Tag::BOOLEAN)?).map_err(cert::Error::Der)?
        } else {
            false
        };
        let value = r.read_tagged(asn1::Tag::OCTET_STRING)?;
        r.finish()?;
        Ok(ExtensionEntry {
            oid,
            critical,
            value,
        })
    }
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = Result<ExtensionEntry<'a>, cert::Error>;

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
    pub fn parse(value: &[u8]) -> Result<Self, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = asn1::Reader::new(inner);
        let ca = if ir.peek_tag() == Some(asn1::Tag::BOOLEAN) {
            if !asn1::Tlv::boolean(ir.read_tagged(asn1::Tag::BOOLEAN)?).map_err(cert::Error::Der)? {
                return Err(cert::Error::Der(asn1::DerError::BadBool));
            }
            true
        } else {
            false
        };
        let path_len_constraint = if ir.peek_tag() == Some(asn1::Tag::INTEGER) {
            if !ca {
                return Err(cert::Error::Der(asn1::DerError::Mismatch));
            }
            Some(asn1::Tlv::integer_u64(ir.read_tagged(asn1::Tag::INTEGER)?)?)
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

    pub fn parse(value: &[u8]) -> Result<Self, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let bs = r.read_tagged(asn1::Tag::BIT_STRING)?;
        r.finish()?;
        if bs.is_empty() {
            return Err(cert::Error::Der(asn1::DerError::BadBitString));
        }
        let unused = bs[0] as usize;
        if unused > 7 {
            return Err(cert::Error::Der(asn1::DerError::BadBitString));
        }
        let content = &bs[1..];
        if content.is_empty() {
            if unused != 0 {
                return Err(cert::Error::Der(asn1::DerError::BadBitString));
            }
            return Ok(Self { bits: 0 });
        }
        if content.len() > 2 {
            return Err(cert::Error::Der(asn1::DerError::BadBitString));
        }
        let last = *content
            .last()
            .ok_or(cert::Error::Der(asn1::DerError::BadBitString))?;
        if unused != 0 && last & ((1u16 << unused) - 1) as u8 != 0 {
            return Err(cert::Error::Der(asn1::DerError::BadBitString));
        }
        if last == 0 {
            return Err(cert::Error::Der(asn1::DerError::BadBitString));
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

    pub fn parse_extended(
        value: &[u8],
    ) -> Result<arrayvec::ArrayVec<&[u8], MAX_EXTENSION_VALUES>, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let mut out = arrayvec::ArrayVec::new();
        let mut ir = asn1::Reader::new(inner);
        while !ir.is_empty() {
            out.try_push(ir.read_tagged(asn1::Tag::OID)?)
                .map_err(|_| cert::Error::TooManyEntries)?;
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
    pub fn parse_alt_names(
        value: &'a [u8],
    ) -> Result<arrayvec::ArrayVec<Self, MAX_EXTENSION_VALUES>, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = asn1::Reader::new(inner);
        let mut out = arrayvec::ArrayVec::new();
        while !ir.is_empty() {
            let tlv = ir.read_tlv()?;
            out.try_push(if tlv.tag == asn1::Tag::context(2, false) {
                Self::DnsName(tlv.contents)
            } else if tlv.tag == asn1::Tag::context(7, false) {
                Self::IpAddress(tlv.contents)
            } else {
                Self::Other {
                    tag: tlv.tag.0,
                    value: tlv.contents,
                }
            })
            .map_err(|_| cert::Error::TooManyEntries)?;
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Subtrees<'a> {
    pub dns: arrayvec::ArrayVec<&'a [u8], MAX_EXTENSION_VALUES>,
    pub ip: arrayvec::ArrayVec<&'a [u8], MAX_EXTENSION_VALUES>,
    pub has_unsupported: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NameConstraints<'a> {
    pub permitted: Subtrees<'a>,
    pub excluded: Subtrees<'a>,
}

impl<'a> NameConstraints<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = asn1::Reader::new(inner);
        let mut nc = Self::default();
        if ir.peek_tag() == Some(asn1::Tag::context(0, true)) {
            nc.permitted = Self::parse_subtrees(ir.read_tlv()?.contents)?;
        }
        if ir.peek_tag() == Some(asn1::Tag::context(1, true)) {
            nc.excluded = Self::parse_subtrees(ir.read_tlv()?.contents)?;
        }
        ir.finish()?;
        Ok(nc)
    }

    fn parse_subtrees(bytes: &'a [u8]) -> Result<Subtrees<'a>, cert::Error> {
        let mut r = asn1::Reader::new(bytes);
        let mut out = Subtrees::default();
        while !r.is_empty() {
            let subtree = r.read_tagged(asn1::Tag::SEQUENCE)?;
            let base = asn1::Reader::new(subtree).read_tlv()?;
            if base.tag == asn1::Tag::context(2, false) {
                out.dns
                    .try_push(base.contents)
                    .map_err(|_| cert::Error::TooManyEntries)?;
            } else if base.tag == asn1::Tag::context(7, false) {
                out.ip
                    .try_push(base.contents)
                    .map_err(|_| cert::Error::TooManyEntries)?;
            } else {
                out.has_unsupported = true;
            }
        }
        Ok(out)
    }
}
