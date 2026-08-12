use shin::wire::codec::{DecodeError, Encode, Reader};
use shin::wire::extension::{Extensions, MAX_EXTENSIONS};
use shin::wire::handshake::MAX_CERTIFICATE_ENTRIES;
use shin::wire::handshake::frame::CertificateRef;
use shin::wire::handshake::messages::{Certificate, CertificateEntry};

#[test]
fn duplicate_extension_type_is_rejected() {
    // Two extensions with the same type (0x002b supported_versions).
    let mut body: Vec<u8> = Vec::new();
    let mut extensions = body.begin_u16().unwrap();
    extensions.put_u16(0x002b);
    let mut data = extensions.begin_u16().unwrap();
    data.put_u8(0);
    data.finish().unwrap();
    extensions.put_u16(0x002b);
    let mut data = extensions.begin_u16().unwrap();
    data.put_u8(0);
    data.finish().unwrap();
    extensions.finish().unwrap();
    let mut r = Reader::new(&body);
    assert_eq!(
        Extensions::decode(&mut r).unwrap_err(),
        DecodeError::DuplicateExtension
    );
}

#[test]
fn distinct_extensions_decode() {
    let mut body: Vec<u8> = Vec::new();
    let mut extensions = body.begin_u16().unwrap();
    extensions.put_u16(0x002b);
    let mut data = extensions.begin_u16().unwrap();
    data.put_u8(0);
    data.finish().unwrap();
    extensions.put_u16(0x000a);
    let mut data = extensions.begin_u16().unwrap();
    data.put_u8(0);
    data.finish().unwrap();
    extensions.finish().unwrap();
    let mut r = Reader::new(&body);
    let exts = Extensions::decode(&mut r).unwrap();
    assert_eq!(exts.iter().count(), 2);
}

#[test]
fn too_many_extensions_rejected() {
    // Distinct extension types beyond the cap must be rejected.
    let mut body: Vec<u8> = Vec::new();
    let mut extensions = body.begin_u16().unwrap();
    for ty in 0..=(MAX_EXTENSIONS as u16) {
        extensions.put_u16(0x8000 + ty);
        let mut data = extensions.begin_u16().unwrap();
        data.put_u8(0);
        data.finish().unwrap();
    }
    extensions.finish().unwrap();
    let mut r = Reader::new(&body);
    assert_eq!(
        Extensions::decode(&mut r).unwrap_err(),
        DecodeError::InvalidEnum
    );
}

#[test]
fn max_extensions_accepted() {
    let mut body: Vec<u8> = Vec::new();
    let mut extensions = body.begin_u16().unwrap();
    for ty in 0..(MAX_EXTENSIONS as u16) {
        extensions.put_u16(0x8000 + ty);
        let mut data = extensions.begin_u16().unwrap();
        data.put_u8(0);
        data.finish().unwrap();
    }
    extensions.finish().unwrap();
    let mut r = Reader::new(&body);
    let exts = Extensions::decode(&mut r).unwrap();
    assert_eq!(exts.iter().count(), MAX_EXTENSIONS);
}

#[test]
fn too_many_certificate_entries_rejected() {
    let entry = CertificateEntry {
        cert_data: vec![0u8; 4],
        extensions: Vec::new(),
    };
    let cert = Certificate {
        certificate_request_context: Vec::new(),
        certificate_list: (0..MAX_CERTIFICATE_ENTRIES + 1)
            .map(|_| entry.clone())
            .collect(),
    };
    let mut bytes = Vec::new();
    cert.encode(&mut bytes).unwrap();
    let mut r = Reader::new(&bytes);
    assert_eq!(
        CertificateRef::decode(&mut r).unwrap_err(),
        DecodeError::TooManyCertificates
    );
}

#[test]
fn max_certificate_entries_accepted() {
    let entry = CertificateEntry {
        cert_data: vec![0u8; 4],
        extensions: Vec::new(),
    };
    let cert = Certificate {
        certificate_request_context: Vec::new(),
        certificate_list: (0..MAX_CERTIFICATE_ENTRIES)
            .map(|_| entry.clone())
            .collect(),
    };
    let mut bytes = Vec::new();
    cert.encode(&mut bytes).unwrap();
    let mut r = Reader::new(&bytes);
    let decoded = CertificateRef::decode(&mut r).unwrap();
    assert_eq!(decoded.certificate_list.len(), MAX_CERTIFICATE_ENTRIES);
}
