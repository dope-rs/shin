use shin::asn1::Tag;
use shin::cert::TimeValue;
use shin::time::UnixTime;

fn utc_time(s: &[u8]) -> TimeValue<'_> {
    TimeValue {
        tag: Tag::UTC_TIME,
        bytes: s,
    }
}

fn gen_time(s: &[u8]) -> TimeValue<'_> {
    TimeValue {
        tag: Tag::GENERALIZED_TIME,
        bytes: s,
    }
}

#[test]
fn utc_time_unix_epoch() {
    let t = utc_time(b"700101000000Z");
    assert_eq!(UnixTime::from_time_value(&t).unwrap(), UnixTime(0));
}

#[test]
fn utc_time_year_2000_window() {
    let t = utc_time(b"000101000000Z");
    assert_eq!(
        UnixTime::from_time_value(&t).unwrap(),
        UnixTime(946_684_800)
    );
}

#[test]
fn utc_time_year_1990_window() {
    let t = utc_time(b"900101000000Z");
    assert_eq!(
        UnixTime::from_time_value(&t).unwrap(),
        UnixTime(631_152_000)
    );
}

#[test]
fn generalized_time_distant_future() {
    let t = gen_time(b"20500101000000Z");
    assert_eq!(
        UnixTime::from_time_value(&t).unwrap(),
        UnixTime(2_524_608_000)
    );
}

#[test]
fn invalid_time_format_rejected() {
    let t = utc_time(b"700101");
    assert!(UnixTime::from_time_value(&t).is_err());
    let t = utc_time(b"7001010000007");
    assert!(UnixTime::from_time_value(&t).is_err());
}

#[test]
fn time_ordering_compares() {
    let a = UnixTime::from_time_value(&utc_time(b"200101000000Z")).unwrap();
    let b = UnixTime::from_time_value(&utc_time(b"210101000000Z")).unwrap();
    assert!(a < b);
}

#[test]
fn leap_year_handled() {
    let jan1 = UnixTime::from_time_value(&utc_time(b"000101000000Z")).unwrap();
    let mar1 = UnixTime::from_time_value(&utc_time(b"000301000000Z")).unwrap();
    assert_eq!(mar1.0 - jan1.0, 60 * 86_400);
}
