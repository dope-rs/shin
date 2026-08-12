use core::mem::size_of;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, date_time_ymd};
use shin::identity::UnixTime;
use shin::identity::cert::{Cert, Error, Validity};

fn certificate(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["time.local".into()]).unwrap();
    params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
    params.self_signed(&key).unwrap().der().to_vec()
}

fn replace_time(der: &mut [u8], encoded: &[u8], replacement: &[u8]) {
    assert_eq!(encoded.len(), replacement.len());
    let offset = der
        .windows(encoded.len())
        .position(|candidate| candidate == encoded)
        .expect("encoded certificate time");
    der[offset..offset + encoded.len()].copy_from_slice(replacement);
}

#[test]
fn parse_materializes_a_lifetime_free_validity_interval() {
    let der = certificate((2020, 1, 1), (2050, 1, 1));
    let validity = Cert::parse(&der).unwrap().tbs.validity;
    assert_eq!(validity.not_before, UnixTime(1_577_836_800));
    assert_eq!(validity.not_after, UnixTime(2_524_608_000));
    assert_eq!(size_of::<Validity>(), 2 * size_of::<UnixTime>());
}

#[test]
fn pre_epoch_x509_time_remains_orderable() {
    let der = certificate((1950, 1, 1), (1970, 1, 1));
    let validity = Cert::parse(&der).unwrap().tbs.validity;
    assert_eq!(validity.not_before, UnixTime(-631_152_000));
    assert_eq!(validity.not_after, UnixTime(0));
    assert_eq!(validity.not_before.as_secs(), None);
}

#[test]
fn maximum_x509_year_converts_without_year_linear_work() {
    let der = certificate((2050, 1, 1), (9999, 1, 1));
    let validity = Cert::parse(&der).unwrap().tbs.validity;
    assert_eq!(validity.not_after, UnixTime(253_370_764_800));
}

#[test]
fn parse_rejects_invalid_calendar_and_time_components() {
    let der = certificate((2020, 1, 1), (2022, 1, 1));
    for invalid in [
        &b"200431000000Z"[..],
        b"210229000000Z",
        b"200230000000Z",
        b"201231235960Z",
        b"2001010000000",
    ] {
        let mut tampered = der.clone();
        replace_time(&mut tampered, b"200101000000Z", invalid);
        assert_eq!(Cert::parse(&tampered).unwrap_err(), Error::BadValidity);
    }

    let mut leap_day = der;
    replace_time(&mut leap_day, b"200101000000Z", b"200229000000Z");
    assert!(Cert::parse(&leap_day).is_ok());
}

#[test]
fn parse_enforces_x509_time_encoding_and_interval_order() {
    let mut noncanonical = certificate((2020, 1, 1), (2050, 1, 1));
    replace_time(&mut noncanonical, b"20500101000000Z", b"20490101000000Z");
    assert_eq!(Cert::parse(&noncanonical).unwrap_err(), Error::BadValidity);

    let mut reversed = certificate((2020, 1, 1), (2022, 1, 1));
    replace_time(&mut reversed, b"200101000000Z", b"230101000000Z");
    assert_eq!(Cert::parse(&reversed).unwrap_err(), Error::BadValidity);
}
