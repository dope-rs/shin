use shin::codec::{DecodeError, Encode, Reader};
use shin::extension::Extension;
use shin::handshake::{Certificate, CertificateEntry, MAX_CERTIFICATE_ENTRIES};

#[test]
fn duplicate_extension_type_is_rejected() {
    // Two extensions with the same type (0x002b supported_versions).
    let mut body: Vec<u8> = Vec::new();
    body.put_vec_u16(|o| {
        o.put_u16(0x002b);
        o.put_vec_u16(|d| d.put_u8(0));
        o.put_u16(0x002b);
        o.put_vec_u16(|d| d.put_u8(0));
    });
    let mut r = Reader::new(&body);
    assert_eq!(
        Extension::decode_list(&mut r).unwrap_err(),
        DecodeError::DuplicateExtension
    );
}

#[test]
fn distinct_extensions_decode() {
    let mut body: Vec<u8> = Vec::new();
    body.put_vec_u16(|o| {
        o.put_u16(0x002b);
        o.put_vec_u16(|d| d.put_u8(0));
        o.put_u16(0x000a);
        o.put_vec_u16(|d| d.put_u8(0));
    });
    let mut r = Reader::new(&body);
    let exts = Extension::decode_list(&mut r).unwrap();
    assert_eq!(exts.len(), 2);
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
    cert.encode(&mut bytes);
    let mut r = Reader::new(&bytes);
    assert_eq!(
        Certificate::decode(&mut r).unwrap_err(),
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
        certificate_list: (0..MAX_CERTIFICATE_ENTRIES).map(|_| entry.clone()).collect(),
    };
    let mut bytes = Vec::new();
    cert.encode(&mut bytes);
    let mut r = Reader::new(&bytes);
    let decoded = Certificate::decode(&mut r).unwrap();
    assert_eq!(decoded.certificate_list.len(), MAX_CERTIFICATE_ENTRIES);
}
