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

    pub fn matches_ip(self, presented: &[u8]) -> bool {
        presented == self.0
    }

    pub fn is_ip_literal(self) -> bool {
        let h = self.0;
        if h.is_empty() {
            return false;
        }
        if h.contains(&b':') {
            return true;
        }
        h.iter().all(|c| c.is_ascii_digit() || *c == b'.')
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
