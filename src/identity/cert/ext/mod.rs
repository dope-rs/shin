use crate::identity::asn1;
use crate::identity::cert;
use core::mem;

pub mod scope;

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
    pub oid: asn1::Oid<'a>,
    pub critical: bool,
    pub value: &'a [u8],
}

impl ExtensionEntry<'_> {
    pub fn is_handled(oid: asn1::Oid<'_>) -> bool {
        matches!(
            oid.as_bytes(),
            OID_KEY_USAGE
                | OID_SUBJECT_ALT_NAME
                | OID_BASIC_CONSTRAINTS
                | OID_NAME_CONSTRAINTS
                | OID_EXTENDED_KEY_USAGE
        )
    }
}

pub struct ExtensionIter<'a> {
    encoded: &'a [u8],
    offset: usize,
    seen: OidFilter,
    count: u8,
}

struct RawExtensionIter<'a> {
    reader: asn1::Reader<'a>,
}

#[derive(Default)]
struct OidFilter(u64);

const _: () = assert!(mem::size_of::<ExtensionIter<'static>>() <= 40);

impl<'a> ExtensionIter<'a> {
    pub fn new(extensions_der: &'a [u8]) -> Self {
        Self {
            encoded: extensions_der,
            offset: 0,
            seen: OidFilter::default(),
            count: 0,
        }
    }

    pub fn find(
        extensions_der: &'a [u8],
        oid: &[u8],
    ) -> Result<Option<(bool, &'a [u8])>, cert::Error> {
        for ext in Self::new(extensions_der) {
            let ext = ext?;
            if ext.oid.is(oid) {
                return Ok(Some((ext.critical, ext.value)));
            }
        }
        Ok(None)
    }

    fn parse_entry(&mut self) -> Result<ExtensionEntry<'a>, cert::Error> {
        let encoded = self.encoded;
        let start = self.offset;
        let remaining = encoded
            .get(start..)
            .ok_or(cert::Error::Der(asn1::DerError::Underflow))?;
        let mut reader = asn1::Reader::new(remaining);
        let entry = parse_extension(&mut reader)?;
        let consumed = remaining
            .len()
            .checked_sub(reader.bytes_remaining().len())
            .ok_or(cert::Error::Der(asn1::DerError::Underflow))?;
        self.offset = start
            .checked_add(consumed)
            .ok_or(cert::Error::TooManyEntries)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(cert::Error::TooManyEntries)?;
        if usize::from(self.count) > MAX_EXTENSION_VALUES {
            return Err(cert::Error::TooManyEntries);
        }
        let prefix = encoded
            .get(..start)
            .ok_or(cert::Error::Der(asn1::DerError::Underflow))?;
        self.seen.admit(entry.oid, prefix)?;
        Ok(entry)
    }
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = Result<ExtensionEntry<'a>, cert::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.encoded.len() {
            return None;
        }
        let entry = self.parse_entry();
        if entry.is_err() {
            self.offset = self.encoded.len();
        }
        Some(entry)
    }
}

impl<'a> RawExtensionIter<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self {
            reader: asn1::Reader::new(encoded),
        }
    }
}

impl<'a> Iterator for RawExtensionIter<'a> {
    type Item = Result<ExtensionEntry<'a>, cert::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some(parse_extension(&mut self.reader))
    }
}

impl OidFilter {
    fn admit(&mut self, oid: asn1::Oid<'_>, prefix: &[u8]) -> Result<(), cert::Error> {
        let bit = Self::bit(oid);
        if self.0 & bit != 0 {
            for previous in RawExtensionIter::new(prefix) {
                if previous?.oid == oid {
                    return Err(cert::Error::DuplicateExtension);
                }
            }
        }
        self.0 |= bit;
        Ok(())
    }

    fn bit(oid: asn1::Oid<'_>) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut hash = OFFSET;
        for byte in oid.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        let [low, ..] = hash.to_le_bytes();
        1u64.rotate_left(u32::from(low & 63))
    }
}

fn parse_extension<'a>(reader: &mut asn1::Reader<'a>) -> Result<ExtensionEntry<'a>, cert::Error> {
    let inner = reader.read_tagged(asn1::Tag::SEQUENCE)?;
    let mut entry = asn1::Reader::new(inner);
    let oid = entry.read_oid()?;
    let critical = if entry.peek_tag() == Some(asn1::Tag::BOOLEAN) {
        if !entry.read_bool()? {
            return Err(cert::Error::Der(asn1::DerError::BadBool));
        }
        true
    } else {
        false
    };
    let value = entry.read_tagged(asn1::Tag::OCTET_STRING)?;
    entry.finish()?;
    Ok(ExtensionEntry {
        oid,
        critical,
        value,
    })
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
            if !ir.read_bool()? {
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
            Some(ir.read_uint()?.to_u64()?)
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
        let bit_string = r.read_bit_string()?;
        r.finish()?;
        let content = bit_string.as_bytes();
        if content.is_empty() || content.len() > 2 {
            return Err(cert::Error::Der(asn1::DerError::BadBitString));
        }
        let last = *content
            .last()
            .ok_or(cert::Error::Der(asn1::DerError::BadBitString))?;
        if last == 0
            || last.trailing_zeros() != u32::from(bit_string.unused_bits())
            || content.len() == 2 && last != 0x80
        {
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
            bits |= 1 << 8;
        }
        Ok(Self { bits })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExtendedKeyUsages<'a> {
    contents: &'a [u8],
}

pub struct ExtendedKeyUsageIter<'a> {
    reader: asn1::Reader<'a>,
}

const _: () = assert!(mem::size_of::<ExtendedKeyUsages<'static>>() <= 16);
const _: () = assert!(mem::size_of::<ExtendedKeyUsageIter<'static>>() <= 16);

impl<'a> ExtendedKeyUsages<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let contents = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let usages = Self { contents };
        let mut count = 0usize;
        for oid in usages.iter() {
            oid?;
            count += 1;
            if count > MAX_EXTENSION_VALUES {
                return Err(cert::Error::TooManyEntries);
            }
        }
        if count == 0 {
            return Err(cert::Error::Der(asn1::DerError::Mismatch));
        }
        Ok(usages)
    }

    pub fn iter(self) -> ExtendedKeyUsageIter<'a> {
        ExtendedKeyUsageIter {
            reader: asn1::Reader::new(self.contents),
        }
    }
}

impl<'a> Iterator for ExtendedKeyUsageIter<'a> {
    type Item = Result<asn1::Oid<'a>, cert::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some(self.reader.read_oid().map_err(cert::Error::Der))
    }
}
