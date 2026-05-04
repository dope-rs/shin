use shin::codec::Reader;
use shin::extension::{Extension, ExtensionType};
use shin::handshake::{
    Certificate, CertificateEntry, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    Handshake, HandshakeType, RANDOM_LEN, ServerHello, TLS_1_2, TLS_1_3,
};

fn sample_extensions() -> Vec<Extension> {
    vec![
        Extension::new(
            ExtensionType::SUPPORTED_VERSIONS,
            vec![0x02, (TLS_1_3 >> 8) as u8, (TLS_1_3 & 0xff) as u8],
        ),
        Extension::new(
            ExtensionType::QUIC_TRANSPORT_PARAMETERS,
            b"transport_params_payload".to_vec(),
        ),
    ]
}

#[test]
fn client_hello_round_trip() {
    let ch = ClientHello {
        legacy_version: TLS_1_2,
        random: [0xAB; RANDOM_LEN],
        legacy_session_id: vec![0x10, 0x20, 0x30],
        cipher_suites: vec![0x1301, 0x1302],
        legacy_compression_methods: vec![0],
        extensions: sample_extensions(),
    };
    let mut buf = Vec::new();
    ch.encode(&mut buf);
    let mut r = Reader::new(&buf);
    let decoded = ClientHello::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, ch);
}

#[test]
fn server_hello_round_trip() {
    let sh = ServerHello {
        legacy_version: TLS_1_2,
        random: [0xCD; RANDOM_LEN],
        legacy_session_id_echo: vec![0x10, 0x20, 0x30],
        cipher_suite: 0x1301,
        legacy_compression_method: 0,
        extensions: sample_extensions(),
    };
    let mut buf = Vec::new();
    sh.encode(&mut buf);
    let mut r = Reader::new(&buf);
    let decoded = ServerHello::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, sh);
}

#[test]
fn encrypted_extensions_round_trip() {
    let ee = EncryptedExtensions {
        extensions: sample_extensions(),
    };
    let mut buf = Vec::new();
    ee.encode(&mut buf);
    let mut r = Reader::new(&buf);
    let decoded = EncryptedExtensions::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, ee);
}

#[test]
fn certificate_round_trip() {
    let cert = Certificate {
        certificate_request_context: vec![],
        certificate_list: vec![
            CertificateEntry {
                cert_data: b"raw-public-key-spki-bytes".to_vec(),
                extensions: vec![],
            },
            CertificateEntry {
                cert_data: b"intermediate".to_vec(),
                extensions: vec![Extension::new(ExtensionType(99), b"x".to_vec())],
            },
        ],
    };
    let mut buf = Vec::new();
    cert.encode(&mut buf);
    let mut r = Reader::new(&buf);
    let decoded = Certificate::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, cert);
}

#[test]
fn certificate_verify_round_trip() {
    let cv = CertificateVerify {
        algorithm: 0x0807,
        signature: b"signature-bytes".to_vec(),
    };
    let mut buf = Vec::new();
    cv.encode(&mut buf);
    let mut r = Reader::new(&buf);
    let decoded = CertificateVerify::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, cv);
}

#[test]
fn finished_round_trip() {
    let fin = Finished {
        verify_data: vec![0xFF; 32],
    };
    let mut buf = Vec::new();
    fin.encode(&mut buf);
    let mut r = Reader::new(&buf);
    let decoded = Finished::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, fin);
}

#[test]
fn handshake_wraps_with_type_and_length() {
    let hs = Handshake::ClientHello(ClientHello {
        legacy_version: TLS_1_2,
        random: [0xAB; RANDOM_LEN],
        legacy_session_id: vec![],
        cipher_suites: vec![0x1301],
        legacy_compression_methods: vec![0],
        extensions: sample_extensions(),
    });
    let mut buf = Vec::new();
    hs.encode(&mut buf);

    assert_eq!(buf[0], HandshakeType::ClientHello as u8);
    let body_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    assert_eq!(body_len + 4, buf.len());

    let mut r = Reader::new(&buf);
    let decoded = Handshake::decode(&mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(decoded, hs);
}

#[test]
fn handshake_round_trip_each_variant() {
    let variants = vec![
        Handshake::ServerHello(ServerHello {
            legacy_version: TLS_1_2,
            random: [0x11; RANDOM_LEN],
            legacy_session_id_echo: vec![1, 2, 3],
            cipher_suite: 0x1301,
            legacy_compression_method: 0,
            extensions: sample_extensions(),
        }),
        Handshake::EncryptedExtensions(EncryptedExtensions {
            extensions: sample_extensions(),
        }),
        Handshake::Certificate(Certificate {
            certificate_request_context: vec![],
            certificate_list: vec![CertificateEntry {
                cert_data: b"spki".to_vec(),
                extensions: vec![],
            }],
        }),
        Handshake::CertificateVerify(CertificateVerify {
            algorithm: 0x0807,
            signature: b"sig".to_vec(),
        }),
        Handshake::Finished(Finished {
            verify_data: vec![0; 32],
        }),
    ];
    for hs in variants {
        let mut buf = Vec::new();
        hs.encode(&mut buf);
        let mut r = Reader::new(&buf);
        let decoded = Handshake::decode(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(decoded, hs);
    }
}

#[test]
fn handshake_decode_rejects_trailing_bytes_in_body() {
    let mut buf = Vec::new();
    Handshake::Finished(Finished {
        verify_data: vec![0; 32],
    })
    .encode(&mut buf);
    buf.extend_from_slice(b"trailing");

    let mut r = Reader::new(&buf);
    let _ = Handshake::decode(&mut r).unwrap();
    assert!(r.finish().is_err());
}

#[test]
fn handshake_decode_rejects_unknown_type() {
    let buf = vec![99u8, 0, 0, 0];
    let mut r = Reader::new(&buf);
    assert!(Handshake::decode(&mut r).is_err());
}
