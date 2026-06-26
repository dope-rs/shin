use shin::Error;
use shin::alert::{Alert, AlertDescription, AlertParseError};
use shin::record::ContentType;

#[test]
fn close_notify_and_user_canceled_are_not_fatal() {
    assert!(!AlertDescription::CloseNotify.is_fatal());
    assert!(!AlertDescription::UserCanceled.is_fatal());
    assert!(AlertDescription::HandshakeFailure.is_fatal());
    assert!(AlertDescription::NoApplicationProtocol.is_fatal());
}

#[test]
fn round_trips_through_body() {
    let a = Alert::fatal(AlertDescription::DecodeError);
    assert_eq!(Alert::parse(&a.body()), Ok(a));
}

#[test]
fn parse_rejects_bad_length_and_unknown() {
    assert_eq!(Alert::parse(&[2]), Err(AlertParseError::BadLength));
    assert_eq!(Alert::parse(&[2, 0, 0]), Err(AlertParseError::BadLength));
    assert_eq!(Alert::parse(&[9, 0]), Err(AlertParseError::BadLevel));
    assert_eq!(
        Alert::parse(&[2, 255]),
        Err(AlertParseError::UnknownDescription)
    );
}

#[test]
fn plaintext_record_is_well_formed() {
    let rec = Alert::fatal(AlertDescription::HandshakeFailure).to_plaintext_record();
    assert_eq!(rec[0], ContentType::Alert as u8);
    assert_eq!(&rec[3..5], &[0, 2]);
    assert_eq!(&rec[5..7], &[2, 40]);
}

#[test]
fn error_maps_to_fatal_alert() {
    let cases = [
        (Error::Decode, AlertDescription::DecodeError),
        (Error::IllegalParameter, AlertDescription::IllegalParameter),
        (
            Error::UnexpectedMessage,
            AlertDescription::UnexpectedMessage,
        ),
        (Error::BadVersion, AlertDescription::ProtocolVersion),
        (Error::MissingExtension, AlertDescription::MissingExtension),
        (
            Error::UnsolicitedExtension,
            AlertDescription::UnsupportedExtension,
        ),
        (
            Error::NoApplicationProtocol,
            AlertDescription::NoApplicationProtocol,
        ),
        (Error::BadCertificate, AlertDescription::BadCertificate),
        (Error::BadFinished, AlertDescription::DecryptError),
        (Error::BadConfig, AlertDescription::InternalError),
    ];
    for (err, want) in cases {
        let alert = err.alert();
        assert_eq!(alert.description, want);
        assert!(alert.description.is_fatal());
        assert_eq!(Alert::parse(&alert.body()), Ok(alert));
    }
}
