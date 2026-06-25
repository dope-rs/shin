use shin::client::{Client, Config, Resumption, Verifier};
use shin::codec::Reader;
use shin::extension::ExtensionType;
use shin::handshake::{ClientHello, Handshake};
use shin::psk::{KX_MODE_PSK_DHE, KxModes, Offer};
use shin::{Epoch, Event};

fn drive_ch(resumption: Option<Resumption>) -> ClientHello {
    let mut c = Client::new(Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0x42u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption,
        enable_early_data: false,
    });
    let evs = c.start().unwrap();
    let ch_bytes = evs
        .into_iter()
        .find_map(|e| match e {
            Event::Send {
                epoch: Epoch::Plaintext,
                data,
            } => Some(data),
            _ => None,
        })
        .unwrap();
    let mut r = Reader::new(&ch_bytes);
    match Handshake::decode(&mut r).unwrap() {
        Handshake::ClientHello(ch) => ch,
        _ => panic!(),
    }
}

#[test]
fn no_resumption_omits_psk_extensions() {
    let ch = drive_ch(None);
    assert!(
        !ch.extensions
            .iter()
            .any(|e| e.ty == ExtensionType::PRE_SHARED_KEY),
    );
    assert!(
        !ch.extensions
            .iter()
            .any(|e| e.ty == ExtensionType::PSK_KEY_EXCHANGE_MODES),
    );
}

#[test]
fn resumption_attaches_psk_kx_modes_and_offer() {
    let ch = drive_ch(Some(Resumption {
        psk: [0x77u8; 32],
        ticket: vec![0xAA; 64],
        ticket_age_add: 0xCAFEBABE,
        age_millis: 12_345,
    }));

    let kx_ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::PSK_KEY_EXCHANGE_MODES)
        .expect("psk_kx_modes ext expected");
    assert_eq!(
        KxModes::decode(&kx_ext.data).unwrap(),
        vec![KX_MODE_PSK_DHE]
    );

    let psk_ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY)
        .expect("pre_shared_key ext expected");
    let (ids, binders) = Offer::decode(&psk_ext.data).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].identity, vec![0xAA; 64]);
    assert_eq!(
        ids[0].obfuscated_ticket_age,
        12_345u32.wrapping_add(0xCAFEBABE),
    );
    assert_eq!(binders.len(), 1);
    assert_eq!(binders[0].len(), 32);
    assert!(
        !binders[0].iter().all(|&b| b == 0),
        "binder must be computed, not placeholder zeros",
    );
}

/// RFC 8446 §4.2.11.2: the binder covers the ClientHello truncated at the start
/// of `binders`, i.e. len - (2 list-len + 1 binder-len + 32) = len - 35 for one
/// SHA-256 binder. A naive len - 32 is off by 3 and breaks interop.
#[test]
fn binder_covers_partial_ch_per_rfc_not_len_minus_32() {
    use shin::hash::Transcript;
    use shin::psk::ResumptionBinder;

    let psk = [0x99u8; 32];
    let resumption = Resumption {
        psk,
        ticket: vec![0x5A; 48],
        ticket_age_add: 7,
        age_millis: 1_000,
    };

    let mut c = Client::new(Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0x42u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: Some(resumption.clone()),
        enable_early_data: false,
    });
    let ch_bytes = c
        .start()
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            Event::Send {
                epoch: Epoch::Plaintext,
                data,
            } => Some(data),
            _ => None,
        })
        .unwrap();

    let ch = match Handshake::decode(&mut Reader::new(&ch_bytes)).unwrap() {
        Handshake::ClientHello(ch) => ch,
        _ => panic!(),
    };
    let on_wire_binder = {
        let psk_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY)
            .unwrap();
        Offer::decode(&psk_ext.data).unwrap().1[0].clone()
    };

    let n = ch_bytes.len();

    let mut t_ok = Transcript::new();
    t_ok.update(&ch_bytes[..n - 35]);
    let expected = ResumptionBinder::compute(&psk, &t_ok.hash());
    assert_eq!(
        on_wire_binder,
        expected.to_vec(),
        "binder must cover len-35"
    );

    // len-32 (off by 3) must NOT match.
    let mut t_bad = Transcript::new();
    t_bad.update(&ch_bytes[..n - 32]);
    let wrong = ResumptionBinder::compute(&psk, &t_bad.hash());
    assert_ne!(on_wire_binder, wrong.to_vec());
}

#[test]
fn pre_shared_key_is_last_extension() {
    let ch = drive_ch(Some(Resumption {
        psk: [0u8; 32],
        ticket: b"t".to_vec(),
        ticket_age_add: 0,
        age_millis: 0,
    }));
    let last = ch.extensions.last().expect("non-empty");
    assert_eq!(last.ty, ExtensionType::PRE_SHARED_KEY);
}
