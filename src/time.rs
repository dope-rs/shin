use crate::asn1::Tag;
use crate::cert::{CertError, TimeValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub u64);

impl UnixTime {
    pub fn from_time_value(tv: &TimeValue<'_>) -> Result<Self, CertError> {
        match tv.tag {
            Tag::UTC_TIME => Self::from_utc(tv.bytes),
            Tag::GENERALIZED_TIME => Self::from_generalized(tv.bytes),
            _ => Err(CertError::BadValidity),
        }
    }

    fn from_utc(bytes: &[u8]) -> Result<Self, CertError> {
        if bytes.len() != 13 || bytes[12] != b'Z' {
            return Err(CertError::BadValidity);
        }
        let yy = Self::digit2(&bytes[0..2])?;
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        let month = Self::digit2(&bytes[2..4])?;
        let day = Self::digit2(&bytes[4..6])?;
        let hour = Self::digit2(&bytes[6..8])?;
        let min = Self::digit2(&bytes[8..10])?;
        let sec = Self::digit2(&bytes[10..12])?;
        Self::to_unix(year, month, day, hour, min, sec).map(Self)
    }

    fn from_generalized(bytes: &[u8]) -> Result<Self, CertError> {
        if bytes.len() != 15 || bytes[14] != b'Z' {
            return Err(CertError::BadValidity);
        }
        let year = Self::digit4(&bytes[0..4])?;
        let month = Self::digit2(&bytes[4..6])?;
        let day = Self::digit2(&bytes[6..8])?;
        let hour = Self::digit2(&bytes[8..10])?;
        let min = Self::digit2(&bytes[10..12])?;
        let sec = Self::digit2(&bytes[12..14])?;
        Self::to_unix(year, month, day, hour, min, sec).map(Self)
    }

    fn digit2(b: &[u8]) -> Result<u32, CertError> {
        if b.len() != 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
            return Err(CertError::BadValidity);
        }
        Ok((b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32)
    }

    fn digit4(b: &[u8]) -> Result<u32, CertError> {
        if b.len() != 4 || !b.iter().all(|c| c.is_ascii_digit()) {
            return Err(CertError::BadValidity);
        }
        let mut v = 0u32;
        for &c in b {
            v = v * 10 + (c - b'0') as u32;
        }
        Ok(v)
    }

    fn to_unix(
        year: u32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> Result<u64, CertError> {
        if !(1970..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day < 1
            || hour > 23
            || min > 59
            || sec > 59
        {
            return Err(CertError::BadValidity);
        }
        let mut month_days =
            [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][(month - 1) as usize];
        if month == 2 && Self::is_leap(year) {
            month_days = 29;
        }
        if day > month_days {
            return Err(CertError::BadValidity);
        }
        let mut days: u64 = 0;
        for y in 1970..year {
            days += if Self::is_leap(y) { 366 } else { 365 };
        }
        let mom = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for (i, d) in mom.iter().enumerate() {
            if (i as u32) + 1 < month {
                days += d;
                if i == 1 && Self::is_leap(year) {
                    days += 1;
                }
            }
        }
        if day == 0 {
            return Err(CertError::BadValidity);
        }
        days += (day as u64) - 1;
        let secs = days * 86_400 + (hour as u64) * 3_600 + (min as u64) * 60 + (sec as u64);
        Ok(secs)
    }

    fn is_leap(y: u32) -> bool {
        (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
    }
}
