use shin::codec::{Encode, EncodeError};

#[test]
fn length_prefixed_vectors_enforce_wire_limits() {
    let mut out = Vec::new();
    let body = vec![7u8; u8::MAX as usize];
    assert_eq!(
        out.put_vec_u8(|out| {
            out.put_slice(&body);
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(out[0], u8::MAX);
    assert_eq!(out.len(), body.len() + 1);

    let mut out = Vec::new();
    let body = vec![0u8; u8::MAX as usize + 1];
    assert_eq!(
        out.put_vec_u8(|out| {
            out.put_slice(&body);
            Ok(())
        }),
        Err(EncodeError::Overflow)
    );
    assert!(out.is_empty());

    let mut out = Vec::new();
    let body = vec![0u8; u16::MAX as usize + 1];
    assert_eq!(
        out.put_vec_u16(|out| {
            out.put_slice(&body);
            Ok(())
        }),
        Err(EncodeError::Overflow)
    );
    assert!(out.is_empty());

    let mut out = Vec::new();
    let body = vec![0u8; 1 << 24];
    assert_eq!(
        out.put_vec_u24(|out| {
            out.put_slice(&body);
            Ok(())
        }),
        Err(EncodeError::Overflow)
    );
    assert!(out.is_empty());
}
