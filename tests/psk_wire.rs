use shin::psk::{KX_MODE_PSK_DHE, KxModes, Offer, PskIdentity, SelectedIdentity};

#[test]
fn kx_modes_round_trip() {
    let modes = vec![KX_MODE_PSK_DHE];
    let bytes = KxModes::encode(&modes);
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], KX_MODE_PSK_DHE);
    let parsed = KxModes::decode(&bytes).unwrap();
    assert_eq!(parsed, modes);
}

#[test]
fn offer_ch_round_trip_one_identity() {
    let ids = vec![PskIdentity {
        identity: b"opaque-ticket-bytes".to_vec(),
        obfuscated_ticket_age: 0xDEADBEEF,
    }];
    let binders = vec![vec![0xAB; 32]];
    let bytes = Offer::encode(&ids, &binders);
    let (got_ids, got_binders) = Offer::decode(&bytes).unwrap();
    assert_eq!(got_ids, ids);
    assert_eq!(got_binders, binders);
}

#[test]
fn offer_ch_round_trip_multiple() {
    let ids = vec![
        PskIdentity {
            identity: b"id-A".to_vec(),
            obfuscated_ticket_age: 1,
        },
        PskIdentity {
            identity: b"id-B".to_vec(),
            obfuscated_ticket_age: 2,
        },
    ];
    let binders = vec![vec![0x11; 32], vec![0x22; 32]];
    let bytes = Offer::encode(&ids, &binders);
    let (got_ids, got_binders) = Offer::decode(&bytes).unwrap();
    assert_eq!(got_ids, ids);
    assert_eq!(got_binders, binders);
}

#[test]
fn selected_sh_round_trip() {
    let bytes = SelectedIdentity::encode(0);
    assert_eq!(SelectedIdentity::decode(&bytes).unwrap(), 0);
    let bytes = SelectedIdentity::encode(0x4321);
    assert_eq!(SelectedIdentity::decode(&bytes).unwrap(), 0x4321);
}
