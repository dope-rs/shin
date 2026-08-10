use shin::connection::Error;
use shin::wire::alert::{Alert, Description};
use shin::wire::record::ContentType;

#[test]
fn close_notify_and_user_canceled_are_not_fatal() {
    assert!(!Description::CloseNotify.is_fatal());
    assert!(!Description::UserCanceled.is_fatal());
    assert!(Description::HandshakeFailure.is_fatal());
    assert!(Description::NoApplicationProtocol.is_fatal());
}

#[test]
fn round_trips_through_body() {
    let a = Alert::fatal(Description::DecodeError);
    assert_eq!(Alert::parse(&a.body()), Ok(a));
}

#[test]
fn parse_rejects_bad_length_and_unknown() {
    assert_eq!(Alert::parse(&[2]), Err(shin::wire::alert::Error::BadLength));
    assert_eq!(
        Alert::parse(&[2, 0, 0]),
        Err(shin::wire::alert::Error::BadLength)
    );
    assert_eq!(
        Alert::parse(&[9, 0]),
        Err(shin::wire::alert::Error::BadLevel)
    );
    assert_eq!(
        Alert::parse(&[2, 255]),
        Err(shin::wire::alert::Error::UnknownDescription)
    );
}

#[test]
fn plaintext_record_is_well_formed() {
    let rec = Alert::fatal(Description::HandshakeFailure)
        .to_plaintext_record()
        .unwrap();
    assert_eq!(rec[0], ContentType::Alert as u8);
    assert_eq!(&rec[3..5], &[0, 2]);
    assert_eq!(&rec[5..7], &[2, 40]);
}

#[test]
fn error_maps_to_fatal_alert() {
    let cases = [
        (Error::Decode, Description::DecodeError),
        (Error::IllegalParameter, Description::IllegalParameter),
        (Error::UnexpectedMessage, Description::UnexpectedMessage),
        (Error::BadVersion, Description::ProtocolVersion),
        (Error::MissingExtension, Description::MissingExtension),
        (
            Error::UnsolicitedExtension,
            Description::UnsupportedExtension,
        ),
        (
            Error::NoApplicationProtocol,
            Description::NoApplicationProtocol,
        ),
        (Error::BadCertificate, Description::BadCertificate),
        (Error::BadFinished, Description::DecryptError),
        (Error::BadConfig, Description::InternalError),
    ];
    for (err, want) in cases {
        let alert = err.alert();
        assert_eq!(alert.description, want);
        assert!(alert.description.is_fatal());
        assert_eq!(Alert::parse(&alert.body()), Ok(alert));
    }
}
