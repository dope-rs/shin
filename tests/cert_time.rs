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
fn leap_second_rejected() {
    // RFC 5280: seconds are 00..=59, so sec == 60 must be rejected.
    assert!(UnixTime::from_time_value(&utc_time(b"201231235960Z")).is_err());
    assert!(UnixTime::from_time_value(&gen_time(b"20201231235960Z")).is_err());
    assert!(UnixTime::from_time_value(&utc_time(b"201231235959Z")).is_ok());
}

#[test]
fn leap_year_handled() {
    let jan1 = UnixTime::from_time_value(&utc_time(b"000101000000Z")).unwrap();
    let mar1 = UnixTime::from_time_value(&utc_time(b"000301000000Z")).unwrap();
    assert_eq!(mar1.0 - jan1.0, 60 * 86_400);
}

#[test]
fn day_of_month_validated_against_month_length() {
    // April has 30 days; April 31 is invalid.
    assert!(UnixTime::from_time_value(&utc_time(b"210431000000Z")).is_err());
    // June 31 invalid; June 30 valid.
    assert!(UnixTime::from_time_value(&utc_time(b"210631000000Z")).is_err());
    assert!(UnixTime::from_time_value(&utc_time(b"210630000000Z")).is_ok());
}

#[test]
fn february_day_validation_with_leap_year() {
    // 2021 is not a leap year: Feb 29 invalid, Feb 28 valid, Feb 30 always invalid.
    assert!(UnixTime::from_time_value(&utc_time(b"210229000000Z")).is_err());
    assert!(UnixTime::from_time_value(&utc_time(b"210228000000Z")).is_ok());
    // 2020 is a leap year: Feb 29 valid, Feb 30 invalid.
    assert!(UnixTime::from_time_value(&utc_time(b"200229000000Z")).is_ok());
    assert!(UnixTime::from_time_value(&utc_time(b"200230000000Z")).is_err());
    // Generalized-time leap century: 2000 is leap.
    assert!(UnixTime::from_time_value(&gen_time(b"20000229000000Z")).is_ok());
}
