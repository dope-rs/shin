use shin::wire::psk::{
    Identity, KX_MODE_DHE, KxModes, KxModesRef, Offer, OfferedPsks, SelectedIdentity,
};

#[test]
fn kx_modes_round_trip() {
    let modes = vec![KX_MODE_DHE];
    let bytes = KxModes::new(modes.clone()).encode().unwrap();
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], KX_MODE_DHE);
    let parsed = KxModesRef::decode(&bytes).unwrap();
    assert_eq!(parsed.as_slice(), modes);
}

#[test]
fn empty_kx_modes_are_rejected() {
    let encoded = KxModes::new(Vec::new()).encode().unwrap();
    assert!(KxModesRef::decode(&encoded).is_err());
}

#[test]
fn offer_ch_round_trip_one_identity() {
    let ids = vec![Identity {
        identity: b"opaque-ticket-bytes".to_vec(),
        obfuscated_ticket_age: 0xDEADBEEF,
    }];
    let binders = vec![vec![0xAB; 32]];
    let bytes = Offer::new(ids.clone(), binders.clone()).encode().unwrap();
    let got = OfferedPsks::decode(&bytes).unwrap().into_owned();
    assert_eq!(got.identities, ids);
    assert_eq!(got.binders, binders);
}

#[test]
fn offer_ch_round_trip_multiple() {
    let ids = vec![
        Identity {
            identity: b"id-A".to_vec(),
            obfuscated_ticket_age: 1,
        },
        Identity {
            identity: b"id-B".to_vec(),
            obfuscated_ticket_age: 2,
        },
    ];
    let binders = vec![vec![0x11; 32], vec![0x22; 32]];
    let bytes = Offer::new(ids.clone(), binders.clone()).encode().unwrap();
    let got = OfferedPsks::decode(&bytes).unwrap().into_owned();
    assert_eq!(got.identities, ids);
    assert_eq!(got.binders, binders);
}

#[test]
fn offered_psks_require_matching_nonempty_lists_and_full_length_binders() {
    fn decode_round_trip(offer: Offer) -> Result<Offer, shin::wire::codec::DecodeError> {
        let encoded = offer.encode().unwrap();
        OfferedPsks::decode(&encoded).map(OfferedPsks::into_owned)
    }

    let identity = Identity {
        identity: b"ticket".to_vec(),
        obfuscated_ticket_age: 7,
    };
    assert!(decode_round_trip(Offer::new(Vec::new(), Vec::new())).is_err());
    assert!(decode_round_trip(Offer::new(vec![identity.clone()], Vec::new())).is_err());
    assert!(decode_round_trip(Offer::new(vec![identity], vec![vec![0; 31]])).is_err());
}

#[test]
fn selected_sh_round_trip() {
    let bytes = SelectedIdentity::new(0).encode();
    assert_eq!(SelectedIdentity::decode(&bytes).unwrap().get(), 0);
    let bytes = SelectedIdentity::new(0x4321).encode();
    assert_eq!(SelectedIdentity::decode(&bytes).unwrap().get(), 0x4321);
}
