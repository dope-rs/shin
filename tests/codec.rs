use shin::wire::codec::{Encode, EncodeError};

#[test]
fn length_prefixed_vectors_enforce_wire_limits() {
    let mut out = Vec::new();
    let body = vec![7u8; u8::MAX as usize];
    let mut frame = out.begin_u8().unwrap();
    frame.put_slice(&body);
    assert_eq!(frame.finish(), Ok(()));
    assert_eq!(out[0], u8::MAX);
    assert_eq!(out.len(), body.len() + 1);

    let mut out = Vec::new();
    let body = vec![0u8; u8::MAX as usize + 1];
    let mut frame = out.begin_u8().unwrap();
    frame.put_slice(&body);
    assert_eq!(frame.finish(), Err(EncodeError::Overflow));
    assert!(out.is_empty());

    let mut out = Vec::new();
    let body = vec![0u8; u16::MAX as usize + 1];
    let mut frame = out.begin_u16().unwrap();
    frame.put_slice(&body);
    assert_eq!(frame.finish(), Err(EncodeError::Overflow));
    assert!(out.is_empty());

    let mut out = Vec::new();
    let body = vec![0u8; 1 << 24];
    let mut frame = out.begin_u24().unwrap();
    frame.put_slice(&body);
    assert_eq!(frame.finish(), Err(EncodeError::Overflow));
    assert!(out.is_empty());
}

#[test]
fn unfinished_length_frame_rolls_back_its_exact_prefix() {
    let mut out = vec![0xaa];
    {
        let mut frame = out.begin_u16().unwrap();
        frame.put_slice(b"discard");
    }
    assert_eq!(out, [0xaa]);

    let mut frame = out.begin_u16().unwrap();
    frame.put_slice(b"ok");
    frame.finish().unwrap();
    assert_eq!(out, [0xaa, 0, 2, b'o', b'k']);
}
