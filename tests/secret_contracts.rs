use shin::crypto::material::{
    ExporterMasterSecret, FinishedKey, FinishedVerifyData, ResumptionMasterSecret, ResumptionPsk,
    TrafficSecret,
};

fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn drop_contracts_are_static() {
    assert_zeroize_on_drop::<TrafficSecret>();
    assert_zeroize_on_drop::<FinishedKey>();
    assert_zeroize_on_drop::<FinishedVerifyData>();
    assert_zeroize_on_drop::<ResumptionMasterSecret>();
    assert_zeroize_on_drop::<ExporterMasterSecret>();
    assert_zeroize_on_drop::<ResumptionPsk>();
}
