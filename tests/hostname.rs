use shin::identity::Hostname;

#[test]
fn exact_match_is_case_insensitive() {
    assert!(Hostname::new(b"example.COM").matches_dns(b"Example.com"));
}

#[test]
fn trailing_dots_normalized() {
    assert!(Hostname::new(b"example.com").matches_dns(b"example.com."));
    assert!(Hostname::new(b"example.com.").matches_dns(b"example.com"));
}

#[test]
fn wildcard_matches_one_label() {
    assert!(Hostname::new(b"foo.example.com").matches_dns(b"*.example.com"));
    assert!(!Hostname::new(b"foo.bar.example.com").matches_dns(b"*.example.com"));
    assert!(!Hostname::new(b"example.com").matches_dns(b"*.example.com"));
}

#[test]
fn partial_label_wildcards_rejected() {
    assert!(!Hostname::new(b"foobar.example.com").matches_dns(b"foo*.example.com"));
    assert!(!Hostname::new(b"foobar.example.com").matches_dns(b"*bar.example.com"));
    assert!(!Hostname::new(b"foo.example.com").matches_dns(b"f*o.example.com"));
}

#[test]
fn embedded_nul_rejected() {
    assert!(!Hostname::new(b"example.com").matches_dns(b"example.com\0.evil.com"));
    assert!(!Hostname::new(b"example.com\0.evil.com").matches_dns(b"example.com"));
    assert!(!Hostname::new(b"exam\0ple.com").matches_dns(b"exam\0ple.com"));
}

#[test]
fn malformed_names_rejected() {
    assert!(!Hostname::new(b"").matches_dns(b""));
    assert!(!Hostname::new(b".example.com").matches_dns(b".example.com"));
    assert!(!Hostname::new(b"a..com").matches_dns(b"a..com"));
    assert!(!Hostname::new(b"a.b.com").matches_dns(b"*.*.com"));
    assert!(!Hostname::new(b"example").matches_dns(b"*"));
    assert!(!Hostname::new(b".com").matches_dns(b"*.com"));
}

#[test]
fn wildcard_only_in_leftmost_label() {
    assert!(!Hostname::new(b"foo.bar.example.com").matches_dns(b"foo.*.example.com"));
    assert!(!Hostname::new(b"foo.bar.baz.com").matches_dns(b"foo.bar.*.com"));
}

#[test]
fn multiple_wildcards_rejected() {
    assert!(!Hostname::new(b"foo.example.com").matches_dns(b"**.example.com"));
    assert!(!Hostname::new(b"axb.example.com").matches_dns(b"*x*.example.com"));
}

#[test]
fn ip_match_byte_equal() {
    assert!(Hostname::new(&[10, 0, 0, 1]).matches_ip(&[10, 0, 0, 1]));
    assert!(!Hostname::new(&[10, 0, 0, 2]).matches_ip(&[10, 0, 0, 1]));
    assert!(!Hostname::new(&[10, 0, 0, 1, 0]).matches_ip(&[10, 0, 0, 1]));
}
