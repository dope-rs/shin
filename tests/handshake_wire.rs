use shin::crypto::sig::SignatureScheme;
use shin::wire::codec::Reader;
use shin::wire::extension::{Extension, Type};
use shin::wire::handshake;
use shin::wire::handshake::messages::{
    Certificate, CertificateEntry, CertificateRequest, CertificateVerify, ClientHello,
    EncryptedExtensions, Finished, KeyUpdate, NewSessionTicket, ServerHello,
};
use shin::wire::handshake::views::{
    CertificateEntryRef, CertificateRef, CertificateVerifyRef, ClientHelloRef,
    EncryptedExtensionsRef, MessageRef, NewSessionTicketRef, ServerHelloRef,
};
use shin::wire::handshake::{Frame, KeyUpdateRequest, RANDOM_LEN, TLS_1_2, TLS_1_3};

fn sample_extensions() -> Vec<Extension> {
    vec![
        Extension::new(
            Type::SUPPORTED_VERSIONS,
            vec![0x02, (TLS_1_3 >> 8) as u8, (TLS_1_3 & 0xff) as u8],
        ),
        Extension::new(
            Type::QUIC_TRANSPORT_PARAMETERS,
            b"transport_params_payload".to_vec(),
        ),
    ]
}

fn sample_frames() -> Vec<Frame> {
    vec![
        Frame::ClientHello(ClientHello {
            legacy_version: TLS_1_2,
            random: [0xAB; RANDOM_LEN],
            legacy_session_id: vec![0x10, 0x20, 0x30],
            cipher_suites: vec![0x1301, 0x1302],
            legacy_compression_methods: vec![0],
            extensions: sample_extensions(),
        }),
        Frame::ServerHello(ServerHello {
            legacy_version: TLS_1_2,
            random: [0x11; RANDOM_LEN],
            legacy_session_id_echo: vec![1, 2, 3],
            cipher_suite: 0x1301,
            legacy_compression_method: 0,
            extensions: sample_extensions(),
        }),
        Frame::EncryptedExtensions(EncryptedExtensions {
            extensions: sample_extensions(),
        }),
        Frame::CertificateRequest(CertificateRequest {
            certificate_request_context: b"context".to_vec(),
            extensions: sample_extensions(),
        }),
        Frame::Certificate(Certificate {
            certificate_request_context: vec![],
            certificate_list: vec![CertificateEntry {
                cert_data: b"spki".to_vec(),
                extensions: vec![],
            }],
        }),
        Frame::CertificateVerify(CertificateVerify {
            algorithm: SignatureScheme::ED25519,
            signature: b"sig".to_vec(),
        }),
        Frame::Finished(Finished {
            verify_data: vec![0; 32],
        }),
        Frame::EndOfEarlyData,
        Frame::KeyUpdate(KeyUpdate {
            request: KeyUpdateRequest::Requested,
        }),
        Frame::NewSessionTicket(NewSessionTicket {
            ticket_lifetime: 86_400,
            ticket_age_add: 0x1020_3040,
            ticket_nonce: vec![1, 2],
            ticket: b"ticket".to_vec(),
            extensions: sample_extensions(),
        }),
    ]
}

fn assert_canonical_acceptance(encoded: &[u8]) {
    let mut reader = Reader::new(encoded);
    if let Ok(message) = MessageRef::decode_from(&mut reader) {
        let consumed = encoded.len() - reader.remaining().len();
        let mut round_trip = Vec::new();
        message.into_owned().encode(&mut round_trip).unwrap();
        assert_eq!(round_trip, encoded[..consumed]);
    }
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
    ch.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf);
    let decoded = ClientHelloRef::decode(&mut r).unwrap().into_owned();
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
    sh.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf);
    let decoded = ServerHelloRef::decode(&mut r).unwrap().into_owned();
    r.finish().unwrap();
    assert_eq!(decoded, sh);
}

#[test]
fn encrypted_extensions_round_trip() {
    let ee = EncryptedExtensions {
        extensions: sample_extensions(),
    };
    let mut buf = Vec::new();
    ee.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf);
    let decoded = EncryptedExtensionsRef::decode(&mut r).unwrap().into_owned();
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
                extensions: vec![Extension::new(Type(99), b"x".to_vec())],
            },
        ],
    };
    let mut buf = Vec::new();
    cert.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf);
    let decoded = CertificateRef::decode(&mut r).unwrap().into_owned();
    r.finish().unwrap();
    assert_eq!(decoded, cert);
}

#[test]
fn nonempty_opaque_vectors_reject_empty_payloads() {
    let empty_certificate = CertificateEntry {
        cert_data: Vec::new(),
        extensions: Vec::new(),
    };
    let mut encoded_certificate = Vec::new();
    empty_certificate.encode(&mut encoded_certificate).unwrap();
    assert!(CertificateEntryRef::decode(&mut Reader::new(&encoded_certificate)).is_err());

    let empty_ticket = NewSessionTicket {
        ticket_lifetime: 86_400,
        ticket_age_add: 0,
        ticket_nonce: Vec::new(),
        ticket: Vec::new(),
        extensions: Vec::new(),
    };
    let mut encoded_ticket = Vec::new();
    empty_ticket.encode(&mut encoded_ticket).unwrap();
    assert!(NewSessionTicketRef::decode(&mut Reader::new(&encoded_ticket)).is_err());
}

#[test]
fn certificate_verify_round_trip() {
    let cv = CertificateVerify {
        algorithm: SignatureScheme::ED25519,
        signature: b"signature-bytes".to_vec(),
    };
    let mut buf = Vec::new();
    cv.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf);
    let decoded = CertificateVerifyRef::decode(&mut r).unwrap().into_owned();
    r.finish().unwrap();
    assert_eq!(decoded, cv);
}

#[test]
fn certificate_verify_preserves_unknown_signature_scheme() {
    let encoded = [0xfe, 0xfe, 0, 1, 0xa5];
    let mut reader = Reader::new(&encoded);
    let decoded = CertificateVerifyRef::decode(&mut reader)
        .unwrap()
        .into_owned();
    reader.finish().unwrap();

    assert_eq!(decoded.algorithm.wire_id(), 0xfefe);
    assert_eq!(decoded.signature, [0xa5]);

    let mut round_trip = Vec::new();
    decoded.encode(&mut round_trip).unwrap();
    assert_eq!(round_trip, encoded);
}

#[test]
fn finished_round_trip() {
    let fin = Finished {
        verify_data: vec![0xFF; 32],
    };
    let mut buf = Vec::new();
    fin.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf);
    let decoded = Finished {
        verify_data: r.take_all().to_vec(),
    };
    r.finish().unwrap();
    assert_eq!(decoded, fin);
}

#[test]
fn handshake_wraps_with_type_and_length() {
    let hs = Frame::ClientHello(ClientHello {
        legacy_version: TLS_1_2,
        random: [0xAB; RANDOM_LEN],
        legacy_session_id: vec![],
        cipher_suites: vec![0x1301],
        legacy_compression_methods: vec![0],
        extensions: sample_extensions(),
    });
    let mut buf = Vec::new();
    hs.encode(&mut buf).unwrap();

    assert_eq!(buf[0], handshake::Type::ClientHello as u8);
    let body_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    assert_eq!(body_len + 4, buf.len());

    let mut r = Reader::new(&buf);
    let decoded = MessageRef::decode_from(&mut r).unwrap().into_owned();
    r.finish().unwrap();
    assert_eq!(decoded, hs);
}

#[test]
fn handshake_round_trip_each_variant() {
    for hs in sample_frames() {
        let mut buf = Vec::new();
        hs.encode(&mut buf).unwrap();
        let mut r = Reader::new(&buf);
        let decoded = MessageRef::decode_from(&mut r).unwrap().into_owned();
        r.finish().unwrap();
        assert_eq!(decoded, hs);
    }
}

#[test]
fn borrowed_and_owned_acceptance_match_for_mutated_corpus() {
    for frame in sample_frames() {
        let mut encoded = Vec::new();
        frame.encode(&mut encoded).unwrap();
        assert_eq!(MessageRef::decode(&encoded).unwrap().into_owned(), frame);

        for end in 0..=encoded.len() {
            assert_canonical_acceptance(&encoded[..end]);
        }
        for index in 0..encoded.len() {
            for replacement in [0, 1, 0x7f, 0xff] {
                let mut mutated = encoded.clone();
                mutated[index] = replacement;
                assert_canonical_acceptance(&mutated);
            }
        }
    }
}

#[test]
fn handshake_decode_rejects_trailing_bytes_in_body() {
    let mut buf = Vec::new();
    Frame::Finished(Finished {
        verify_data: vec![0; 32],
    })
    .encode(&mut buf)
    .unwrap();
    buf.extend_from_slice(b"trailing");

    let mut r = Reader::new(&buf);
    let _ = MessageRef::decode_from(&mut r).unwrap();
    assert!(r.finish().is_err());
}

#[test]
fn handshake_decode_rejects_unknown_type() {
    let buf = vec![99u8, 0, 0, 0];
    let mut r = Reader::new(&buf);
    assert!(MessageRef::decode_from(&mut r).is_err());
}
