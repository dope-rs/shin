use core::convert::Infallible;

use rcgen::{
    CertificateParams, CustomExtension, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519,
};

use shin::connection::{DriveError, Epoch, Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use shin::identity::asn1::{Reader, Tag};
use shin::server::config::{CertSource, Config, Connection};
use shin::server::{ReplayDomain, Server, Shard};
use shin::transport::Mode;

struct Ignore;

impl EventSink for Ignore {
    type Error = Infallible;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn raw_config() -> Config {
    Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn invalid_x509_config() -> Config {
    Config {
        source: CertSource::X509 {
            chain_der: Vec::new(),
            signing_key: SigningKey::from_seed(&[8; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn large_x509_config(extension_len: usize) -> Config {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let seed = extract_ed25519_seed(&key.serialize_der()).unwrap();
    let mut params = CertificateParams::new(vec!["large.shin.local".into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55_555, 1],
            vec![0xA5; extension_len],
        ));
    let certificate = params.self_signed(&key).unwrap().der().to_vec();
    Config {
        source: CertSource::X509 {
            chain_der: vec![certificate],
            signing_key: SigningKey::from_seed(&seed).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut outer = Reader::new(pkcs8);
    let sequence = outer.read_tagged(Tag::SEQUENCE).ok()?;
    let mut sequence = Reader::new(sequence);
    sequence.read_tagged(Tag::INTEGER).ok()?;
    sequence.read_tagged(Tag::SEQUENCE).ok()?;
    let private_key = sequence.read_tagged(Tag::OCTET_STRING).ok()?;
    let mut private_key = Reader::new(private_key);
    private_key
        .read_tagged(Tag::OCTET_STRING)
        .ok()?
        .try_into()
        .ok()
}

#[test]
fn fallible_shard_constructor_rejects_invalid_identity_immediately() {
    assert_eq!(
        Shard::try_new(invalid_x509_config()).err(),
        Some(shin::connection::Error::BadConfig),
    );
}

#[test]
fn compatibility_constructor_caches_bad_config_and_then_poison() {
    let mut shard = Shard::new(invalid_x509_config());
    let mut server = Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
    );
    let mut events = Ignore;

    assert_eq!(
        server.read_into(Epoch::Plaintext, &[], &mut shard, &mut events),
        Err(DriveError::Protocol(shin::connection::Error::BadConfig)),
    );
    assert_eq!(
        server.read_into(Epoch::Plaintext, &[], &mut shard, &mut events),
        Err(DriveError::Protocol(
            shin::connection::Error::ConnectionFailed,
        )),
    );
}

#[test]
fn exact_flight_preflight_preserves_large_tls_identity_but_rejects_quic_sum() {
    let shard = Shard::try_new(large_x509_config(200_000)).unwrap();
    let tls = Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
    );
    assert_eq!(tls.validate_shard(&shard), Ok(()));

    let quic = Server::new_with_transport(
        Connection {
            transport_params: vec![0; 65_000],
        },
        Mode::Quic,
        || 0,
    );
    assert_eq!(
        quic.validate_shard(&shard),
        Err(shin::connection::Error::BadConfig),
    );
}

#[test]
fn replay_domain_is_an_explicit_cloneable_namespace_token() {
    let domain = ReplayDomain::new([0xA5; 16]);
    assert_eq!(domain, domain.clone());

    // Creating ordinary shards still needs no caller-provided namespace.
    Shard::try_new(raw_config()).unwrap();
}
