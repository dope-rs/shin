use shin::psk::{KX_MODE_PSK_DHE, KxModes, Offer, PskIdentity, SelectedIdentity};

#[test]
fn kx_modes_round_trip() {
    let modes = vec![KX_MODE_PSK_DHE];
    let bytes = KxModes::new(modes.clone()).encode().unwrap();
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], KX_MODE_PSK_DHE);
    let parsed = KxModes::decode(&bytes).unwrap();
    assert_eq!(parsed.as_slice(), modes);
}

#[test]
fn offer_ch_round_trip_one_identity() {
    let ids = vec![PskIdentity {
        identity: b"opaque-ticket-bytes".to_vec(),
        obfuscated_ticket_age: 0xDEADBEEF,
    }];
    let binders = vec![vec![0xAB; 32]];
    let bytes = Offer::new(ids.clone(), binders.clone()).encode().unwrap();
    let got = Offer::decode(&bytes).unwrap();
    assert_eq!(got.identities, ids);
    assert_eq!(got.binders, binders);
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
    let bytes = Offer::new(ids.clone(), binders.clone()).encode().unwrap();
    let got = Offer::decode(&bytes).unwrap();
    assert_eq!(got.identities, ids);
    assert_eq!(got.binders, binders);
}

#[test]
fn selected_sh_round_trip() {
    let bytes = SelectedIdentity::new(0).encode();
    assert_eq!(SelectedIdentity::decode(&bytes).unwrap().get(), 0);
    let bytes = SelectedIdentity::new(0x4321).encode();
    assert_eq!(SelectedIdentity::decode(&bytes).unwrap().get(), 0x4321);
}
