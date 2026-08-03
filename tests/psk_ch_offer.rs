use shin::client::Client;
use shin::client::config::{Config, Resumption, Verifier};
use shin::connection::Epoch;
use shin::wire::codec::Reader;
use shin::wire::extension::ExtensionType;
use shin::wire::handshake::frame::Frame;
use shin::wire::handshake::messages::ClientHello;
use shin::wire::psk::{KX_MODE_PSK_DHE, KxModes, Offer};

mod common;
use common::{CollectEvents, Event};

fn drive_ch(resumption: Option<Resumption>) -> ClientHello {
    let mut c = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0x42u8; 32],
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption,
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
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
    match Frame::decode(&mut r).unwrap() {
        Frame::ClientHello(ch) => ch,
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
    let ch = drive_ch(Some(Resumption::new(
        [0x77u8; 32],
        vec![0xAA; 64],
        0xCAFEBABE,
        12_345,
    )));

    let kx_ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::PSK_KEY_EXCHANGE_MODES)
        .expect("psk_kx_modes ext expected");
    assert_eq!(
        KxModes::decode(&kx_ext.data).unwrap().as_slice(),
        &[KX_MODE_PSK_DHE]
    );

    let psk_ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY)
        .expect("pre_shared_key ext expected");
    let offer = Offer::decode(&psk_ext.data).unwrap();
    assert_eq!(offer.identities.len(), 1);
    assert_eq!(offer.identities[0].identity, vec![0xAA; 64]);
    assert_eq!(
        offer.identities[0].obfuscated_ticket_age,
        12_345u32.wrapping_add(0xCAFEBABE),
    );
    assert_eq!(offer.binders.len(), 1);
    assert_eq!(offer.binders[0].len(), 32);
    assert!(
        !offer.binders[0].iter().all(|&b| b == 0),
        "binder must be computed, not placeholder zeros",
    );
}

/// RFC 8446 §4.2.11.2: the binder covers the ClientHello truncated at the start
/// of `binders`, i.e. len - (2 list-len + 1 binder-len + 32) = len - 35 for one
/// SHA-256 binder. A naive len - 32 is off by 3 and breaks interop.
#[test]
fn binder_covers_partial_ch_per_rfc_not_len_minus_32() {
    use shin::crypto::hash::{HashAlg, Transcript};
    use shin::wire::psk::ResumptionBinder;

    let psk = [0x99u8; 32];
    let resumption = Resumption::new(psk, vec![0x5A; 48], 7, 1_000);

    let mut c = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0x42u8; 32],
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: Some(resumption),
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
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

    let ch = match Frame::decode(&mut Reader::new(&ch_bytes)).unwrap() {
        Frame::ClientHello(ch) => ch,
        _ => panic!(),
    };
    let on_wire_binder = {
        let psk_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY)
            .unwrap();
        Offer::decode(&psk_ext.data).unwrap().binders[0].clone()
    };

    let n = ch_bytes.len();

    let mut t_ok = Transcript::new();
    t_ok.update(&ch_bytes[..n - 35]);
    let expected = ResumptionBinder::compute(&psk, t_ok.hash(HashAlg::Sha256).as_slice()).unwrap();
    assert_eq!(
        on_wire_binder,
        expected.as_slice().to_vec(),
        "binder must cover len-35"
    );

    // len-32 (off by 3) must NOT match.
    let mut t_bad = Transcript::new();
    t_bad.update(&ch_bytes[..n - 32]);
    let wrong = ResumptionBinder::compute(&psk, t_bad.hash(HashAlg::Sha256).as_slice()).unwrap();
    assert_ne!(on_wire_binder, wrong.as_slice().to_vec());
}

#[test]
fn pre_shared_key_is_last_extension() {
    let ch = drive_ch(Some(Resumption::new([0u8; 32], b"t".to_vec(), 0, 0)));
    let last = ch.extensions.last().expect("non-empty");
    assert_eq!(last.ty, ExtensionType::PRE_SHARED_KEY);
}
