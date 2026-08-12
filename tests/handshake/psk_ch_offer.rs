use shin::client::config::{Config, Restore, Verifier};
use shin::connection::Epoch;
use shin::wire::codec::Reader;
use shin::wire::extension::Type;
use shin::wire::handshake::frame::Frame;
use shin::wire::handshake::messages::ClientHello;
use shin::wire::psk::{KX_MODE_DHE, KxModesRef, OfferedPsks};
use shin::wire::record::CipherSuite;

use crate::common::{CollectEvents, Event};

fn restored(psk: [u8; 32], ticket: Vec<u8>, age_add: u32) -> Restore<'static> {
    Restore::try_new(psk, ticket, age_add, 0, 7_200).unwrap()
}

fn drive_ch(restore: Option<Restore<'static>>, suites: &[CipherSuite]) -> ClientHello {
    drive_ch_at(restore, suites, 0)
}

fn drive_ch_at(
    restore: Option<Restore<'static>>,
    suites: &[CipherSuite],
    now_ms: u64,
) -> ClientHello {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0x42u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
    .try_into_template()
    .unwrap();
    let prepared = match restore {
        Some(restore) => template.restore(restore).unwrap(),
        None => template.without_resumption(),
    };
    let workspace = prepared.workspace_layout(None).allocate();
    let mut c = prepared
        .try_into_client_with_workspace(None, move || now_ms, workspace)
        .unwrap();
    c.set_cipher_suites(suites).unwrap();
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
    match crate::decode_owned(&mut r).unwrap() {
        Frame::ClientHello(ch) => ch,
        _ => panic!(),
    }
}

#[test]
fn no_resumption_omits_psk_extensions() {
    let ch = drive_ch(None, &CipherSuite::SUPPORTED);
    assert!(!ch.extensions.iter().any(|e| e.ty == Type::PRE_SHARED_KEY),);
    assert!(
        !ch.extensions
            .iter()
            .any(|e| e.ty == Type::PSK_KEY_EXCHANGE_MODES),
    );
}

#[test]
fn resumption_attaches_psk_kx_modes_and_offer() {
    let ch = drive_ch_at(
        Some(Restore::try_new([0x77u8; 32], vec![0xAA; 64], 0xCAFEBABE, 5_000, 7_200).unwrap()),
        &CipherSuite::SUPPORTED,
        17_345,
    );

    let kx_ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == Type::PSK_KEY_EXCHANGE_MODES)
        .expect("psk_kx_modes ext expected");
    assert_eq!(
        KxModesRef::decode(&kx_ext.data).unwrap().as_slice(),
        &[KX_MODE_DHE]
    );

    let psk_ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == Type::PRE_SHARED_KEY)
        .expect("pre_shared_key ext expected");
    let offer = OfferedPsks::decode(&psk_ext.data).unwrap().into_owned();
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

#[test]
fn expired_resumption_is_omitted() {
    let ch = drive_ch_at(
        Some(Restore::try_new([0x77; 32], vec![0xAA], 9, 5_000, 1).unwrap()),
        &CipherSuite::SUPPORTED,
        6_001,
    );

    assert!(
        !ch.extensions
            .iter()
            .any(|e| matches!(e.ty, Type::PSK_KEY_EXCHANGE_MODES | Type::PRE_SHARED_KEY))
    );
}

#[test]
fn resumption_is_omitted_when_clock_precedes_receipt() {
    let ch = drive_ch_at(
        Some(Restore::try_new([0x77; 32], vec![0xAA], 9, 5_000, 1).unwrap()),
        &CipherSuite::SUPPORTED,
        4_999,
    );

    assert!(
        !ch.extensions
            .iter()
            .any(|e| matches!(e.ty, Type::PSK_KEY_EXCHANGE_MODES | Type::PRE_SHARED_KEY))
    );
}

/// RFC 8446 §4.2.11.2: the binder covers the ClientHello truncated at the start
/// of `binders`, i.e. len - (2 list-len + 1 binder-len + 32) = len - 35 for one
/// SHA-256 binder. A naive len - 32 is off by 3 and breaks interop.
#[test]
fn binder_covers_partial_ch_per_rfc_not_len_minus_32() {
    use shin::crypto::hash::{Algorithm, Transcript};
    use shin::wire::psk::ResumptionBinder;

    let psk = [0x99u8; 32];
    let restore = restored(psk, vec![0x5A; 48], 7);

    let prepared = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0x42u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
    .try_into_template()
    .unwrap()
    .restore(restore)
    .unwrap();
    let workspace = prepared.workspace_layout(None).allocate();
    let mut c = prepared
        .try_into_client_with_workspace(None, || 0, workspace)
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

    let ch = match crate::decode_owned(&mut Reader::new(&ch_bytes)).unwrap() {
        Frame::ClientHello(ch) => ch,
        _ => panic!(),
    };
    let on_wire_binder = {
        let psk_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == Type::PRE_SHARED_KEY)
            .unwrap();
        OfferedPsks::decode(&psk_ext.data)
            .unwrap()
            .binders()
            .next()
            .unwrap()
            .to_vec()
    };

    let n = ch_bytes.len();

    let mut t_ok = Transcript::new();
    t_ok.update(&ch_bytes[..n - 35]);
    let expected =
        ResumptionBinder::compute(&psk, t_ok.hash(Algorithm::Sha256).unwrap().as_slice()).unwrap();
    assert_eq!(
        on_wire_binder,
        expected.as_slice().to_vec(),
        "binder must cover len-35"
    );

    // len-32 (off by 3) must NOT match.
    let mut t_bad = Transcript::new();
    t_bad.update(&ch_bytes[..n - 32]);
    let wrong =
        ResumptionBinder::compute(&psk, t_bad.hash(Algorithm::Sha256).unwrap().as_slice()).unwrap();
    assert_ne!(on_wire_binder, wrong.as_slice().to_vec());
}

#[test]
fn pre_shared_key_is_last_extension() {
    let ch = drive_ch(
        Some(restored([0u8; 32], b"t".to_vec(), 0)),
        &CipherSuite::SUPPORTED,
    );
    let last = ch.extensions.last().expect("non-empty");
    assert_eq!(last.ty, Type::PRE_SHARED_KEY);
}

#[test]
fn sha256_resumption_is_omitted_from_sha384_only_offer() {
    let ch = drive_ch(
        Some(restored([0u8; 32], b"t".to_vec(), 0)),
        &[CipherSuite::Aes256GcmSha384],
    );

    assert!(!ch.extensions.iter().any(|extension| matches!(
        extension.ty,
        Type::PSK_KEY_EXCHANGE_MODES | Type::PRE_SHARED_KEY
    )),);
}
