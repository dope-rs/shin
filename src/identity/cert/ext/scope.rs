use crate::identity::asn1;
use crate::identity::cert;
use core::mem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralName<'a> {
    DnsName(&'a [u8]),
    IpAddress(&'a [u8]),
    Other { tag: u8, value: &'a [u8] },
}

impl<'a> GeneralName<'a> {
    fn from_tlv(tlv: asn1::Tlv<'a>) -> Result<Self, cert::Error> {
        match tlv.tag.0 {
            0x82 => Ok(Self::DnsName(tlv.contents)),
            0x87 => Ok(Self::IpAddress(tlv.contents)),
            0xa0 | 0x81 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x88 => Ok(Self::Other {
                tag: tlv.tag.0,
                value: tlv.contents,
            }),
            _ => Err(cert::Error::BadName),
        }
    }

    pub(crate) fn dns_in_subtree(name: &[u8], constraint: &[u8]) -> bool {
        let (constraint, subdomains_only) = match constraint.split_first() {
            Some((b'.', rest)) => (rest, true),
            _ => (constraint, false),
        };
        if !subdomains_only && ascii_case_eq(name, constraint) {
            return true;
        }
        name.len() > constraint.len()
            && name[name.len() - constraint.len() - 1] == b'.'
            && ascii_case_eq(&name[name.len() - constraint.len()..], constraint)
    }

    pub(crate) fn ip_in_subtree(address: &[u8], network_and_mask: &[u8]) -> bool {
        if network_and_mask.len() != address.len() * 2 {
            return false;
        }
        let (network, mask) = network_and_mask.split_at(address.len());
        address
            .iter()
            .zip(network)
            .zip(mask)
            .all(|((address, network), mask)| (address & mask) == (network & mask))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GeneralNames<'a> {
    contents: &'a [u8],
}

pub struct GeneralNameIter<'a> {
    reader: asn1::Reader<'a>,
}

const _: () = assert!(mem::size_of::<GeneralNames<'static>>() <= 16);
const _: () = assert!(mem::size_of::<GeneralNameIter<'static>>() <= 16);

impl<'a> GeneralNames<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let contents = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;

        let view = Self { contents };
        let mut count = 0usize;
        for name in view.iter() {
            validate_general_name(name?, false)?;
            count += 1;
            if count > super::MAX_EXTENSION_VALUES {
                return Err(cert::Error::TooManyEntries);
            }
        }
        if count == 0 {
            return Err(cert::Error::BadName);
        }
        Ok(view)
    }

    pub(crate) fn from_validated_contents(contents: &'a [u8]) -> Self {
        Self { contents }
    }

    pub(crate) fn contents(self) -> &'a [u8] {
        self.contents
    }

    pub fn iter(self) -> GeneralNameIter<'a> {
        GeneralNameIter {
            reader: asn1::Reader::new(self.contents),
        }
    }
}

impl<'a> Iterator for GeneralNameIter<'a> {
    type Item = Result<GeneralName<'a>, cert::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some(
            self.reader
                .read_tlv()
                .map_err(cert::Error::Der)
                .and_then(GeneralName::from_tlv),
        )
    }
}

const SUBTREE_DNS: u8 = 1 << 0;
const SUBTREE_IP: u8 = 1 << 1;
const SUBTREE_UNSUPPORTED: u8 = 1 << 2;

#[derive(Debug, Clone, Copy, Default)]
pub struct Subtrees<'a> {
    contents: Option<&'a [u8]>,
    kinds: u8,
    pub(crate) count: u8,
}

pub struct SubtreeIter<'a> {
    reader: asn1::Reader<'a>,
}

impl<'a> Subtrees<'a> {
    fn parse(contents: &'a [u8]) -> Result<Self, cert::Error> {
        let mut reader = asn1::Reader::new(contents);
        let mut count = 0usize;
        let mut kinds = 0u8;
        while !reader.is_empty() {
            let subtree = reader.read_tagged(asn1::Tag::SEQUENCE)?;
            let mut subtree_reader = asn1::Reader::new(subtree);
            let base = GeneralName::from_tlv(subtree_reader.read_tlv()?)?;
            validate_general_name(base, true)?;
            subtree_reader.finish()?;

            kinds |= match base {
                GeneralName::DnsName(_) => SUBTREE_DNS,
                GeneralName::IpAddress(_) => SUBTREE_IP,
                GeneralName::Other { .. } => SUBTREE_UNSUPPORTED,
            };
            count += 1;
            if count > super::MAX_EXTENSION_VALUES {
                return Err(cert::Error::TooManyEntries);
            }
        }
        if count == 0 {
            return Err(cert::Error::BadName);
        }
        Ok(Self {
            contents: Some(contents),
            kinds,
            count: u8::try_from(count).map_err(|_| cert::Error::TooManyEntries)?,
        })
    }

    pub fn has_unsupported(self) -> bool {
        self.kinds & SUBTREE_UNSUPPORTED != 0
    }

    pub fn dns_is_empty(self) -> bool {
        self.kinds & SUBTREE_DNS == 0
    }

    pub fn ip_is_empty(self) -> bool {
        self.kinds & SUBTREE_IP == 0
    }

    pub fn dns_matches(self, name: &[u8]) -> Result<bool, cert::Error> {
        for subtree in self.iter() {
            if let GeneralName::DnsName(constraint) = subtree?
                && GeneralName::dns_in_subtree(name, constraint)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn ip_matches(self, address: &[u8]) -> Result<bool, cert::Error> {
        for subtree in self.iter() {
            if let GeneralName::IpAddress(network) = subtree?
                && GeneralName::ip_in_subtree(address, network)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn iter(self) -> SubtreeIter<'a> {
        SubtreeIter {
            reader: asn1::Reader::new(self.contents.unwrap_or(&[])),
        }
    }
}

impl<'a> Iterator for SubtreeIter<'a> {
    type Item = Result<GeneralName<'a>, cert::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some(
            self.reader
                .read_tagged(asn1::Tag::SEQUENCE)
                .map_err(cert::Error::Der)
                .and_then(|subtree| {
                    let mut reader = asn1::Reader::new(subtree);
                    GeneralName::from_tlv(reader.read_tlv()?)
                }),
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NameConstraints<'a> {
    pub permitted: Subtrees<'a>,
    pub excluded: Subtrees<'a>,
}

const _: () = assert!(mem::size_of::<NameConstraints<'static>>() <= 64);

impl<'a> NameConstraints<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, cert::Error> {
        let mut r = asn1::Reader::new(value);
        let inner = r.read_tagged(asn1::Tag::SEQUENCE)?;
        r.finish()?;
        let mut ir = asn1::Reader::new(inner);
        let mut permitted = Subtrees::default();
        let mut excluded = Subtrees::default();
        let mut present = false;
        if let Some(contents) = ir.read_optional(asn1::Tag::context(0, true))? {
            permitted = Subtrees::parse(contents)?;
            present = true;
        }
        if let Some(contents) = ir.read_optional(asn1::Tag::context(1, true))? {
            excluded = Subtrees::parse(contents)?;
            present = true;
        }
        ir.finish()?;
        if !present {
            return Err(cert::Error::BadName);
        }
        Ok(Self {
            permitted,
            excluded,
        })
    }
}

fn validate_general_name(name: GeneralName<'_>, constraint: bool) -> Result<(), cert::Error> {
    match name {
        GeneralName::DnsName(value) => {
            if !value.is_ascii() || value.is_empty() || value.contains(&0) {
                return Err(cert::Error::BadName);
            }
            if constraint && !valid_dns_constraint(value) {
                return Err(cert::Error::BadName);
            }
        }
        GeneralName::IpAddress(value) => {
            let valid = if constraint {
                matches!(value.len(), 8 | 32) && contiguous_ip_mask(value)
            } else {
                matches!(value.len(), 4 | 16)
            };
            if !valid {
                return Err(cert::Error::BadName);
            }
        }
        GeneralName::Other { tag, value } => {
            if matches!(tag, 0x81 | 0x86) && (!value.is_ascii() || value.contains(&0)) {
                return Err(cert::Error::BadName);
            }
        }
    }
    Ok(())
}

fn valid_dns_constraint(value: &[u8]) -> bool {
    let value = value.strip_prefix(b".").unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.first().is_some_and(u8::is_ascii_alphanumeric)
                && label.last().is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn contiguous_ip_mask(network_and_mask: &[u8]) -> bool {
    let (_, mask) = network_and_mask.split_at(network_and_mask.len() / 2);
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                zero_seen = true;
            } else if zero_seen {
                return false;
            }
        }
    }
    true
}

fn ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}
