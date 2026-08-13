use shin::client::Client;
use shin::client::config::{Config, OwnedTrustAnchor, Verifier};
use shin::connection::Epoch;
use shin::wire::codec::Reader;
use shin::wire::extension::Type;
use shin::wire::handshake::Frame;
use shin::wire::handshake::messages::ClientHello;

use crate::common::{CollectEvents, Event};

fn drive_client_hello(verifier: Verifier) -> ClientHello {
    let mut c = Client::new(
        Config {
            verifier,
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    let evs = c.start().unwrap();
    let ch_bytes = evs
        .into_iter()
        .find_map(|e| match e {
            Event::Send {
                epoch: Epoch::Plaintext,
                data,
            } => Some(data),
            _ => None,
        })
        .expect("ClientHello sent at Plaintext epoch");
    let mut r = Reader::new(&ch_bytes);
    match crate::decode_owned(&mut r).unwrap() {
        Frame::ClientHello(ch) => ch,
        _ => panic!("expected ClientHello"),
    }
}

fn x509_verifier(hostname: &[u8]) -> Verifier {
    let root = &webpki_roots::TLS_SERVER_ROOTS[0];
    Verifier::X509 {
        anchors: vec![OwnedTrustAnchor::from_der_fields(
            root.subject.as_ref(),
            root.subject_public_key_info.as_ref(),
            root.name_constraints.as_ref().map(|value| value.as_ref()),
        )],
        hostname: hostname.to_vec(),
        certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
    }
}

fn find_sni(ch: &ClientHello) -> Option<&[u8]> {
    ch.extensions
        .iter()
        .find(|e| e.ty == Type::SERVER_NAME)
        .map(|e| e.data.as_slice())
}

#[test]
fn x509_emits_server_name_for_dns_hostname() {
    let ch = drive_client_hello(x509_verifier(b"example.com"));
    let data = find_sni(&ch).expect("SNI present for DNS hostname");
    let mut r = Reader::new(data);
    let mut list = r.sub_u16().unwrap();
    let name_type = list.u8().unwrap();
    let name = list.vec_u16().unwrap();
    assert_eq!(name_type, 0);
    assert_eq!(name, b"example.com");
    assert!(list.is_empty());
}

#[test]
fn rpk_does_not_emit_server_name() {
    let ch = drive_client_hello(Verifier::RawPublicKey {
        expected_pubkey: [0x42u8; 32],
    });
    assert!(
        find_sni(&ch).is_none(),
        "RPK ClientHello must not include SNI",
    );
}

#[test]
fn x509_skips_server_name_for_ipv4_literal() {
    let ch = drive_client_hello(x509_verifier(b"192.168.1.1"));
    assert!(find_sni(&ch).is_none(), "IPv4 literal forbidden in SNI");
}

#[test]
fn x509_skips_server_name_for_ipv6_literal() {
    let ch = drive_client_hello(x509_verifier(b"2001:db8::1"));
    assert!(find_sni(&ch).is_none(), "IPv6 literal forbidden in SNI");
}
