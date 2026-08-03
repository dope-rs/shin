use arrayvec::ArrayVec;
use core::str;

#[derive(Clone, Copy)]
pub struct Hostname<'a>(&'a [u8]);

impl<'a> Hostname<'a> {
    pub fn new(reference: &'a [u8]) -> Self {
        Self(reference)
    }

    pub fn matches_dns(self, presented: &[u8]) -> bool {
        let presented = Self::trim_trailing_dot(presented);
        let reference = Self::trim_trailing_dot(self.0);

        if !Self::valid_name(presented) || !Self::valid_name(reference) {
            return false;
        }

        if let Some((wildcard_label, rest_pattern)) = Self::split_first_label(presented) {
            if wildcard_label == b"*" {
                if Self::memchr(b'.', rest_pattern).is_none() {
                    return false;
                }
                let Some((ref_label, ref_rest)) = Self::split_first_label(reference) else {
                    return false;
                };
                if ref_label.is_empty() {
                    return false;
                }
                return Self::ascii_case_eq(ref_rest, rest_pattern);
            }
            if wildcard_label.contains(&b'*') {
                return false;
            }
        } else if presented.contains(&b'*') {
            return false;
        }
        Self::ascii_case_eq(presented, reference)
    }

    fn valid_name(name: &[u8]) -> bool {
        if name.is_empty() || name.contains(&0) {
            return false;
        }
        if name.first() == Some(&b'.') || name.last() == Some(&b'.') {
            return false;
        }
        !name.windows(2).any(|w| w == b"..")
    }

    /// Validates a configured certificate reference identity before any
    /// network operation. DNS references are ASCII A-labels without wildcard
    /// or a trailing root dot; IP references must parse completely.
    pub(crate) fn is_valid_reference(self) -> bool {
        if self.parse_ip().is_some() {
            return true;
        }
        let name = self.0;
        if name.is_empty() || name.len() > 253 || name.ends_with(b".") {
            return false;
        }
        name.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.first().is_some_and(u8::is_ascii_alphanumeric)
                && label.last().is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
    }

    pub fn matches_ip(self, presented: &[u8]) -> bool {
        presented == self.0
    }

    pub fn is_ip_literal(self) -> bool {
        self.parse_ip().is_some()
    }

    pub(crate) fn parse_ip(self) -> Option<ArrayVec<u8, 16>> {
        let text = str::from_utf8(self.0).ok()?;
        if text.contains(':') {
            Self::parse_ipv6(text)
        } else {
            Self::parse_ipv4(text)
        }
    }

    fn parse_ipv4(text: &str) -> Option<ArrayVec<u8, 16>> {
        let mut parts = text.split('.');
        let mut out = ArrayVec::new();
        for _ in 0..4 {
            let part = parts.next()?;
            if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            out.try_push(part.parse::<u8>().ok()?).ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(out)
    }

    fn parse_ipv6(text: &str) -> Option<ArrayVec<u8, 16>> {
        let (head, tail, compressed) = match text.find("::") {
            Some(index) => {
                if text[index + 2..].contains("::") {
                    return None;
                }
                (&text[..index], &text[index + 2..], true)
            }
            None => (text, "", false),
        };

        let (head_bytes, head_groups) = Self::parse_v6_part(head)?;
        let (tail_bytes, tail_groups) = Self::parse_v6_part(tail)?;

        if compressed {
            let total = head_groups + tail_groups;
            if total >= 8 {
                return None;
            }
            let mut out = ArrayVec::new();
            out.try_extend_from_slice(&head_bytes).ok()?;
            for _ in 0..(8 - total) * 2 {
                out.try_push(0).ok()?;
            }
            out.try_extend_from_slice(&tail_bytes).ok()?;
            Some(out)
        } else if head_groups == 8 && tail.is_empty() {
            Some(head_bytes)
        } else {
            None
        }
    }

    fn parse_v6_part(part: &str) -> Option<(ArrayVec<u8, 16>, usize)> {
        if part.is_empty() {
            return Some((ArrayVec::new(), 0));
        }
        let mut tokens = part.split(':').peekable();
        let mut out = ArrayVec::new();
        let mut groups = 0;
        while let Some(token) = tokens.next() {
            if token.contains('.') {
                if tokens.peek().is_some() {
                    return None;
                }
                out.try_extend_from_slice(&Self::parse_ipv4(token)?).ok()?;
                groups += 2;
            } else {
                if token.is_empty()
                    || token.len() > 4
                    || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return None;
                }
                out.try_extend_from_slice(&u16::from_str_radix(token, 16).ok()?.to_be_bytes())
                    .ok()?;
                groups += 1;
            }
        }
        Some((out, groups))
    }

    fn trim_trailing_dot(s: &[u8]) -> &[u8] {
        if s.ends_with(b".") {
            &s[..s.len() - 1]
        } else {
            s
        }
    }

    fn ascii_case_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len()
            && a.iter()
                .zip(b.iter())
                .all(|(x, y)| x.eq_ignore_ascii_case(y))
    }

    fn split_first_label(host: &[u8]) -> Option<(&[u8], &[u8])> {
        let dot = Self::memchr(b'.', host)?;
        Some((&host[..dot], &host[dot + 1..]))
    }

    fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
        haystack.iter().position(|&b| b == needle)
    }
}
