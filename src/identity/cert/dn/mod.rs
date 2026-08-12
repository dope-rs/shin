use crate::identity::asn1;
use crate::identity::cert;
use core::mem;
use core::str;
use ring::digest;

mod profile;

const MAX_ATTRIBUTES_PER_RDN: usize = 64;
const DOMAIN_COMPONENT_OID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];

#[derive(Debug, Clone, Copy)]
pub struct DistinguishedName<'a> {
    der: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NameKey([u8; digest::SHA256_OUTPUT_LEN]);

#[derive(Clone, Copy)]
struct Attribute<'a> {
    oid: asn1::Oid<'a>,
    value: asn1::Tlv<'a>,
}

#[derive(Debug, Clone, Copy)]
struct Rdn<'a> {
    der: &'a [u8],
    count: u8,
}

struct AttributeIter<'a> {
    reader: asn1::Reader<'a>,
}

#[derive(Default)]
struct AttributeSetHash([u8; digest::SHA256_OUTPUT_LEN]);

const _: () = assert!(mem::size_of::<Rdn<'static>>() <= 24);
const _: () = assert!(mem::size_of::<AttributeIter<'static>>() <= 16);
const _: () = assert!(
    mem::size_of::<AttributeSetHash>() == mem::size_of::<[u8; digest::SHA256_OUTPUT_LEN]>()
);

impl<'a> DistinguishedName<'a> {
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, cert::Error> {
        validate_name(der)?;
        Ok(Self { der })
    }

    pub(crate) fn prepared(der: &'a [u8]) -> Result<(Self, NameKey), cert::Error> {
        let key = NameKey::new(der)?;
        Ok((Self { der }, key))
    }

    pub fn as_der(&self) -> &'a [u8] {
        self.der
    }

    pub(crate) fn from_validated(der: &'a [u8]) -> Self {
        Self { der }
    }

    pub(crate) fn equivalent(self, other: Self) -> bool {
        self.der == other.der || names_equal(self.der, other.der)
    }
}

impl NameKey {
    fn new(der: &[u8]) -> Result<Self, cert::Error> {
        let mut name = asn1::Reader::new(der);
        let mut hash = digest::Context::new(&digest::SHA256);
        let mut rdn_count = 0usize;
        while !name.is_empty() {
            let rdn = name.read_tagged(asn1::Tag::SET)?;
            hash_rdn(rdn, &mut hash)?;
            rdn_count = rdn_count
                .checked_add(1)
                .ok_or(cert::Error::TooManyEntries)?;
        }
        hash_length(&mut hash, rdn_count)?;
        Ok(Self(finish_hash(hash)))
    }
}

fn validate_name(der: &[u8]) -> Result<(), cert::Error> {
    let mut name = asn1::Reader::new(der);
    while !name.is_empty() {
        let rdn = name.read_tagged(asn1::Tag::SET)?;
        Rdn::scan(rdn, validate_attribute)?;
    }
    Ok(())
}

fn validate_attribute(attribute: Attribute<'_>) -> Result<(), cert::Error> {
    if let Some(value) = case_ignore_string(attribute)? {
        validate_directory_string(value)?;
    } else {
        string_value(attribute.value)?;
    }
    Ok(())
}

fn hash_rdn(der: &[u8], hash: &mut digest::Context) -> Result<(), cert::Error> {
    let mut attributes = AttributeSetHash::default();
    let rdn = Rdn::scan(der, |attribute| {
        attributes.insert(hash_attribute(attribute)?);
        Ok(())
    })?;
    hash.update(&u64::from(rdn.count).to_be_bytes());
    hash.update(&attributes.0);
    Ok(())
}

fn hash_attribute(
    attribute: Attribute<'_>,
) -> Result<[u8; digest::SHA256_OUTPUT_LEN], cert::Error> {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash_attribute_into(attribute, &mut hash)?;
    Ok(finish_hash(hash))
}

fn hash_attribute_into(
    attribute: Attribute<'_>,
    hash: &mut digest::Context,
) -> Result<(), cert::Error> {
    hash_length(hash, attribute.oid.as_bytes().len())?;
    hash.update(attribute.oid.as_bytes());
    if is_domain_component(attribute) {
        hash.update(&[1]);
        for byte in attribute.value.contents {
            hash.update(&[byte.to_ascii_lowercase()]);
        }
    } else if let Some(value) = case_ignore_string(attribute)? {
        hash.update(&[2]);
        validate_directory_string(value)?;
        for character in profile::Profile::new(value) {
            hash.update(&u32::from(character).to_be_bytes());
        }
    } else {
        hash.update(&[3, attribute.value.tag.0]);
        hash_length(hash, attribute.value.contents.len())?;
        hash.update(attribute.value.contents);
    }
    Ok(())
}

fn finish_hash(hash: digest::Context) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let mut output = [0; digest::SHA256_OUTPUT_LEN];
    output.copy_from_slice(hash.finish().as_ref());
    output
}

fn hash_length(hash: &mut digest::Context, value: usize) -> Result<(), cert::Error> {
    let value = u64::try_from(value).map_err(|_| cert::Error::TooManyEntries)?;
    hash.update(&value.to_be_bytes());
    Ok(())
}

impl<'a> Rdn<'a> {
    fn parse(der: &'a [u8]) -> Result<Self, cert::Error> {
        Self::scan(der, validate_attribute)
    }

    fn scan(
        der: &'a [u8],
        mut visit: impl FnMut(Attribute<'a>) -> Result<(), cert::Error>,
    ) -> Result<Self, cert::Error> {
        let mut count = 0u8;
        for attribute in AttributeIter::new(der) {
            visit(attribute?)?;
            count = count.checked_add(1).ok_or(cert::Error::TooManyEntries)?;
            if usize::from(count) > MAX_ATTRIBUTES_PER_RDN {
                return Err(cert::Error::TooManyEntries);
            }
        }
        if count == 0 {
            return Err(cert::Error::BadName);
        }
        Ok(Self { der, count })
    }

    fn iter(self) -> AttributeIter<'a> {
        AttributeIter::new(self.der)
    }
}

impl<'a> AttributeIter<'a> {
    fn new(der: &'a [u8]) -> Self {
        Self {
            reader: asn1::Reader::new(der),
        }
    }
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = Result<Attribute<'a>, cert::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some((|| {
            let sequence = self.reader.read_tagged(asn1::Tag::SEQUENCE)?;
            let mut entry = asn1::Reader::new(sequence);
            let oid = entry.read_oid()?;
            let value = entry.read_tlv()?;
            entry.finish()?;
            Ok(Attribute { oid, value })
        })())
    }
}

impl AttributeSetHash {
    /// Adds an attribute digest modulo 2^256. Addition makes the aggregate
    /// independent of DER SET order while retaining duplicate multiplicity.
    /// NameKey is only an index filter; exact DN comparison remains mandatory.
    fn insert(&mut self, digest: [u8; digest::SHA256_OUTPUT_LEN]) {
        let mut carry = 0u16;
        for (sum, addend) in self.0.iter_mut().rev().zip(digest.iter().rev()) {
            let value = u16::from(*sum) + u16::from(*addend) + carry;
            let [low, _] = value.to_le_bytes();
            *sum = low;
            carry = value >> 8;
        }
    }
}

fn names_equal(left: &[u8], right: &[u8]) -> bool {
    let mut left = asn1::Reader::new(left);
    let mut right = asn1::Reader::new(right);
    while !left.is_empty() && !right.is_empty() {
        let (Ok(left_rdn), Ok(right_rdn)) = (left.read_tlv(), right.read_tlv()) else {
            return false;
        };
        if left_rdn.tag != asn1::Tag::SET
            || right_rdn.tag != asn1::Tag::SET
            || !rdns_equal(left_rdn.contents, right_rdn.contents)
        {
            return false;
        }
    }
    left.is_empty() && right.is_empty()
}

fn rdns_equal(left: &[u8], right: &[u8]) -> bool {
    let Ok(left) = Rdn::parse(left) else {
        return false;
    };
    let Ok(right) = Rdn::parse(right) else {
        return false;
    };
    if left.count != right.count {
        return false;
    }
    let mut matched = 0u64;
    for left_attribute in left.iter() {
        let Ok(left_attribute) = left_attribute else {
            return false;
        };
        let mut found = false;
        let mut bit = 1u64;
        for right_attribute in right.iter() {
            let Ok(right_attribute) = right_attribute else {
                return false;
            };
            if matched & bit == 0 && attributes_equal(left_attribute, right_attribute) {
                matched |= bit;
                found = true;
                break;
            }
            bit = bit.rotate_left(1);
        }
        if !found {
            return false;
        }
    }
    true
}

fn attributes_equal(left: Attribute<'_>, right: Attribute<'_>) -> bool {
    if left.oid != right.oid {
        return false;
    }
    if is_domain_component(left) && is_domain_component(right) {
        return left
            .value
            .contents
            .eq_ignore_ascii_case(right.value.contents);
    }
    match (case_ignore_string(left), case_ignore_string(right)) {
        (Ok(Some(left)), Ok(Some(right))) => {
            profile::Profile::new(left).eq(profile::Profile::new(right))
        }
        (Ok(None), Ok(None)) => {
            left.value.tag == right.value.tag && left.value.contents == right.value.contents
        }
        _ => false,
    }
}

fn is_domain_component(attribute: Attribute<'_>) -> bool {
    attribute.oid.is(DOMAIN_COMPONENT_OID)
        && attribute.value.tag == asn1::Tag::IA5_STRING
        && attribute.value.contents.is_ascii()
}

fn case_ignore_string(attribute: Attribute<'_>) -> Result<Option<&str>, cert::Error> {
    if case_ignore_oid(attribute.oid) {
        string_value(attribute.value)
    } else {
        Ok(None)
    }
}

fn case_ignore_oid(oid: asn1::Oid<'_>) -> bool {
    let [0x55, 0x04, attribute] = oid.as_bytes() else {
        return false;
    };
    matches!(
        attribute,
        3..=13 | 15 | 17..=19 | 27 | 41..=44 | 46 | 51 | 54 | 65 | 97
    )
}

fn string_value(value: asn1::Tlv<'_>) -> Result<Option<&str>, cert::Error> {
    match value.tag {
        asn1::Tag::UTF8_STRING => str::from_utf8(value.contents)
            .map(Some)
            .map_err(|_| cert::Error::BadName),
        asn1::Tag::PRINTABLE_STRING => {
            if value.contents.iter().all(|byte| printable(*byte)) {
                str::from_utf8(value.contents)
                    .map(Some)
                    .map_err(|_| cert::Error::BadName)
            } else {
                Err(cert::Error::BadName)
            }
        }
        _ => Ok(None),
    }
}

fn printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
}

fn validate_directory_string(value: &str) -> Result<(), cert::Error> {
    if profile::Profile::is_valid(value) {
        Ok(())
    } else {
        Err(cert::Error::BadName)
    }
}
