use o3::buffer;
use shin::wire::record::{ContentType, Error, Opener, Sealer};

const TEST_SECRET: [u8; 32] = [
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
];

#[test]
fn tls_record_writes_directly_to_a_safe_o3_transaction() {
    let pool = buffer::pool::Pool::try_new(1, 128).unwrap();
    let mut output = pool.try_acquire_buffer().unwrap();
    let mut sealer = Sealer::from_secret(&TEST_SECRET).unwrap();

    {
        let mut writer = output.spare_writer();
        assert_eq!(
            sealer
                .seal_parts_to(ContentType::ApplicationData, 4, [&b"abc"[..]], &mut writer)
                .unwrap_err(),
            Error::LengthMismatch
        );
        assert_eq!(
            writer.len(),
            0,
            "failed records roll back before the writer drops"
        );

        sealer
            .seal_to(
                ContentType::ApplicationData,
                b"safe direct output",
                &mut writer,
            )
            .unwrap();
    }

    let mut wire = output.as_slice().to_vec();
    let mut opener = Opener::from_secret(&TEST_SECRET).unwrap();
    let (content_type, range, _) = opener.open(&mut wire).unwrap().unwrap();

    assert_eq!(content_type, ContentType::ApplicationData);
    assert_eq!(&wire[range], b"safe direct output");
}
