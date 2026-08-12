pub mod asn1;
pub mod cert;
pub mod chain;
mod hostname;
pub(crate) mod leafkey;
pub mod spki;

pub use hostname::Hostname;

/// A certificate representation selected by TLS certificate-type negotiation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    X509 = 0,
    RawPublicKey = 2,
}

impl CertificateType {
    pub const fn wire_id(self) -> u8 {
        self as u8
    }

    pub(crate) const fn from_wire_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::X509),
            2 => Some(Self::RawPublicKey),
            _ => None,
        }
    }
}

const _: () = assert!(core::mem::size_of::<CertificateType>() == 1);
const _: () = assert!(core::mem::size_of::<Option<CertificateType>>() == 1);

/// Signed UNIX seconds, including pre-epoch X.509 validity bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub i64);

impl UnixTime {
    /// Converts non-negative seconds, saturating beyond the signed domain.
    pub const fn from_secs(seconds: u64) -> Self {
        if seconds > i64::MAX as u64 {
            Self(i64::MAX)
        } else {
            Self(seconds as i64)
        }
    }

    pub const fn as_secs(&self) -> Option<u64> {
        if self.0 < 0 {
            None
        } else {
            Some(self.0 as u64)
        }
    }

    pub(crate) fn from_x509(tag: asn1::Tag, bytes: &[u8]) -> Result<Self, cert::Error> {
        use crate::identity::asn1::Tag;
        match tag {
            Tag::UTC_TIME => Self::from_utc(bytes),
            Tag::GENERALIZED_TIME => Self::from_generalized(bytes),
            _ => Err(cert::Error::BadValidity),
        }
    }

    fn from_utc(bytes: &[u8]) -> Result<Self, cert::Error> {
        if bytes.len() != 13 || bytes[12] != b'Z' {
            return Err(cert::Error::BadValidity);
        }
        let yy = Self::digit2(&bytes[0..2])?;
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        let month = Self::digit2(&bytes[2..4])?;
        let day = Self::digit2(&bytes[4..6])?;
        let hour = Self::digit2(&bytes[6..8])?;
        let min = Self::digit2(&bytes[8..10])?;
        let sec = Self::digit2(&bytes[10..12])?;
        Self::from_components(year, month, day, hour, min, sec)
    }

    fn from_generalized(bytes: &[u8]) -> Result<Self, cert::Error> {
        if bytes.len() != 15 || bytes[14] != b'Z' {
            return Err(cert::Error::BadValidity);
        }
        let year = Self::digit4(&bytes[0..4])?;
        if year < 2050 {
            return Err(cert::Error::BadValidity);
        }
        let month = Self::digit2(&bytes[4..6])?;
        let day = Self::digit2(&bytes[6..8])?;
        let hour = Self::digit2(&bytes[8..10])?;
        let min = Self::digit2(&bytes[10..12])?;
        let sec = Self::digit2(&bytes[12..14])?;
        Self::from_components(year, month, day, hour, min, sec)
    }

    fn digit2(b: &[u8]) -> Result<u32, cert::Error> {
        if b.len() != 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
            return Err(cert::Error::BadValidity);
        }
        Ok((b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32)
    }

    fn digit4(b: &[u8]) -> Result<u32, cert::Error> {
        if b.len() != 4 || !b.iter().all(|c| c.is_ascii_digit()) {
            return Err(cert::Error::BadValidity);
        }
        let mut v = 0u32;
        for &c in b {
            v = v * 10 + (c - b'0') as u32;
        }
        Ok(v)
    }

    fn from_components(
        year: u32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> Result<Self, cert::Error> {
        if !(1950..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day < 1
            || hour > 23
            || min > 59
            || sec > 59
        {
            return Err(cert::Error::BadValidity);
        }
        let mut month_days =
            [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][(month - 1) as usize];
        if month == 2 && Self::is_leap(year) {
            month_days = 29;
        }
        if day > month_days {
            return Err(cert::Error::BadValidity);
        }

        const DAYS_BEFORE_MONTH: [i64; 12] =
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        let years = i64::from(year) - 1970;
        let mut days = years * 365 + Self::leaps_before(year) - Self::leaps_before(1970);
        days += DAYS_BEFORE_MONTH[(month - 1) as usize];
        if month > 2 && Self::is_leap(year) {
            days += 1;
        }
        days += i64::from(day - 1);
        Ok(Self(
            days * 86_400 + i64::from(hour) * 3_600 + i64::from(min) * 60 + i64::from(sec),
        ))
    }

    fn is_leap(y: u32) -> bool {
        (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
    }

    fn leaps_before(year: u32) -> i64 {
        let year = year - 1;
        i64::from(year / 4 - year / 100 + year / 400)
    }
}
