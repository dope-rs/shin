use shin::hostname::Hostname;

#[test]
fn exact_match_is_case_insensitive() {
    assert!(Hostname::dns_matches(b"Example.com", b"example.COM"));
}

#[test]
fn trailing_dots_normalized() {
    assert!(Hostname::dns_matches(b"example.com.", b"example.com"));
    assert!(Hostname::dns_matches(b"example.com", b"example.com."));
}

#[test]
fn wildcard_matches_one_label() {
    assert!(Hostname::dns_matches(b"*.example.com", b"foo.example.com"));
    assert!(!Hostname::dns_matches(
        b"*.example.com",
        b"foo.bar.example.com"
    ));
    assert!(!Hostname::dns_matches(b"*.example.com", b"example.com"));
}

#[test]
fn partial_label_wildcards_rejected() {
    // Hardened: only a full single-label "*" is a valid wildcard.
    assert!(!Hostname::dns_matches(
        b"foo*.example.com",
        b"foobar.example.com"
    ));
    assert!(!Hostname::dns_matches(
        b"*bar.example.com",
        b"foobar.example.com"
    ));
    assert!(!Hostname::dns_matches(
        b"f*o.example.com",
        b"foo.example.com"
    ));
}

#[test]
fn embedded_nul_rejected() {
    assert!(!Hostname::dns_matches(
        b"example.com\0.evil.com",
        b"example.com"
    ));
    assert!(!Hostname::dns_matches(
        b"example.com",
        b"example.com\0.evil.com"
    ));
    assert!(!Hostname::dns_matches(b"exam\0ple.com", b"exam\0ple.com"));
}

#[test]
fn malformed_names_rejected() {
    assert!(!Hostname::dns_matches(b"", b""));
    assert!(!Hostname::dns_matches(b".example.com", b".example.com"));
    assert!(!Hostname::dns_matches(b"a..com", b"a..com"));
    assert!(!Hostname::dns_matches(b"*.*.com", b"a.b.com"));
    assert!(!Hostname::dns_matches(b"*", b"example"));
    assert!(!Hostname::dns_matches(b"*.com", b".com"));
}

#[test]
fn wildcard_only_in_leftmost_label() {
    assert!(!Hostname::dns_matches(
        b"foo.*.example.com",
        b"foo.bar.example.com"
    ));
    assert!(!Hostname::dns_matches(b"foo.bar.*.com", b"foo.bar.baz.com"));
}

#[test]
fn multiple_wildcards_rejected() {
    assert!(!Hostname::dns_matches(
        b"**.example.com",
        b"foo.example.com"
    ));
    assert!(!Hostname::dns_matches(
        b"*x*.example.com",
        b"axb.example.com"
    ));
}

#[test]
fn ip_match_byte_equal() {
    assert!(Hostname::ip_matches(&[10, 0, 0, 1], &[10, 0, 0, 1]));
    assert!(!Hostname::ip_matches(&[10, 0, 0, 1], &[10, 0, 0, 2]));
    assert!(!Hostname::ip_matches(&[10, 0, 0, 1], &[10, 0, 0, 1, 0]));
}
