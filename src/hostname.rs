pub struct Hostname;

impl Hostname {
    pub fn dns_matches(presented: &[u8], reference: &[u8]) -> bool {
        let presented = Self::trim_trailing_dot(presented);
        let reference = Self::trim_trailing_dot(reference);

        if let Some((wildcard_part, rest_pattern)) = Self::split_wildcard(presented) {
            let Some((ref_label, ref_rest)) = Self::split_first_label(reference) else {
                return false;
            };
            if !Self::ascii_case_eq(ref_rest, rest_pattern) {
                return false;
            }
            Self::wildcard_label_matches(wildcard_part, ref_label)
        } else {
            Self::ascii_case_eq(presented, reference)
        }
    }

    pub fn ip_matches(presented: &[u8], reference: &[u8]) -> bool {
        presented == reference
    }

    pub fn is_ip_literal(h: &[u8]) -> bool {
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

    fn split_wildcard(presented: &[u8]) -> Option<(&[u8], &[u8])> {
        let dot = Self::memchr(b'.', presented)?;
        let leftmost = &presented[..dot];
        if !leftmost.contains(&b'*') {
            return None;
        }
        Some((leftmost, &presented[dot + 1..]))
    }

    fn split_first_label(host: &[u8]) -> Option<(&[u8], &[u8])> {
        let dot = Self::memchr(b'.', host)?;
        Some((&host[..dot], &host[dot + 1..]))
    }

    fn wildcard_label_matches(pattern: &[u8], label: &[u8]) -> bool {
        let star_idx = match Self::memchr(b'*', pattern) {
            Some(i) => i,
            None => return Self::ascii_case_eq(pattern, label),
        };
        if pattern[star_idx + 1..].contains(&b'*') {
            return false;
        }
        let prefix = &pattern[..star_idx];
        let suffix = &pattern[star_idx + 1..];
        if label.len() < prefix.len() + suffix.len() {
            return false;
        }
        let label_prefix = &label[..prefix.len()];
        let label_suffix = &label[label.len() - suffix.len()..];
        if !Self::ascii_case_eq(label_prefix, prefix) || !Self::ascii_case_eq(label_suffix, suffix)
        {
            return false;
        }
        label.len() > prefix.len() + suffix.len()
    }

    fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
        haystack.iter().position(|&b| b == needle)
    }
}
