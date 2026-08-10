//! Dependency-free release benchmark for Shin's per-connection ceilings.
//!
//! Run with `cargo bench --bench perf_ceiling`. Set `SHIN_BENCH_SCALE` to a
//! positive integer to multiply every iteration count. Results are descriptive:
//! deterministic size/allocation limits remain enforced by `resource_profiles`.

use std::convert::Infallible;
use std::hint::black_box;
use std::mem::{self, size_of};
use std::time::Instant;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use ring::rand::SystemRandom;

use shin::client::config::{OwnedTrustAnchor, Resumption, Template, Verifier};
use shin::client::{self, Client};
use shin::connection::{Epoch, Event, EventContext, EventSink};
use shin::crypto::kx::{EphemeralKey, KexGroup, SharedSecret};
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::identity::UnixTime;
use shin::identity::asn1::{Reader, Tag};
use shin::identity::cert::Cert;
use shin::server::config::CertSource;
use shin::server::{self, Server, Shard};
use shin::wire::handshake::frame::Frame;
use shin::wire::handshake::workspace::Scratch;
use shin::wire::record::{ContentType, Opener, Sealer};
use shin::wire::{codec, extension};

const HOSTNAME: &str = "bench.shin.local";
const TICKET_KEY: [u8; 32] = [0x33; 32];
const TRAFFIC_SECRET: [u8; 32] = [0xA5; 32];

#[derive(Default)]
struct Captured {
    plaintext: Vec<u8>,
    handshake: Vec<u8>,
    application: Vec<u8>,
    psk: Option<[u8; 32]>,
    ticket: Option<(u32, Vec<u8>)>,
    wire_bytes: usize,
    done: bool,
}

impl Captured {
    fn take(&mut self, epoch: Epoch) -> Vec<u8> {
        match epoch {
            Epoch::Plaintext => mem::take(&mut self.plaintext),
            Epoch::Handshake => mem::take(&mut self.handshake),
            Epoch::Application => mem::take(&mut self.application),
            Epoch::EarlyData => panic!("benchmark driver does not enable early data"),
        }
    }
}

impl EventSink for Captured {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => {
                self.wire_bytes += data.len();
                match epoch {
                    Epoch::Plaintext => self.plaintext.extend_from_slice(data),
                    Epoch::Handshake => self.handshake.extend_from_slice(data),
                    Epoch::Application => self.application.extend_from_slice(data),
                    Epoch::EarlyData => panic!("benchmark driver does not enable early data"),
                }
            }
            Event::ResumptionSecret { psk } => self.psk = Some(*psk.as_array()),
            Event::NewSessionTicket {
                ticket_age_add,
                ticket,
                ..
            } => self.ticket = Some((ticket_age_add, ticket.to_vec())),
            Event::Done => self.done = true,
            Event::KeysReady { .. }
            | Event::PeerExtension { .. }
            | Event::KeyUpdate { .. }
            | Event::ZeroRttKeysReady { .. }
            | Event::EarlyDataAccepted
            | Event::EarlyDataRejected => {}
        }
        Ok(())
    }
}

#[derive(Clone)]
struct TicketFixture {
    psk: [u8; 32],
    ticket: Vec<u8>,
    age_add: u32,
}

impl TicketFixture {
    fn resumption(&self) -> Resumption {
        Resumption::new(self.psk, self.ticket.clone(), self.age_add, 0)
    }
}

struct HandshakeOutcome {
    wire_bytes: usize,
    ticket: Option<TicketFixture>,
}

fn drive_handshake(
    template: &Template,
    resumption: Option<Resumption>,
    shard: &mut Shard,
    initial_group: KexGroup,
    now_ms: u64,
) -> HandshakeOutcome {
    let prepared = match resumption {
        Some(resumption) => template
            .clone()
            .with_resumption(Some(resumption))
            .expect("benchmark resumption config"),
        None => template.clone().without_resumption(),
    };
    let mut client =
        Client::with_prepared_workspace(prepared, None, move || now_ms, Scratch::for_client());
    client
        .set_kex_group(initial_group)
        .expect("set initial benchmark KX group");
    let mut server = Server::new(
        server::config::Connection {
            transport_params: Vec::new(),
        },
        move || now_ms,
    );

    let mut total_wire_bytes = 0;
    let mut client_start = Captured::default();
    client
        .start_into(&mut client_start)
        .expect("start benchmark client");
    total_wire_bytes += client_start.wire_bytes;
    let client_hello = client_start.take(Epoch::Plaintext);

    let mut server_flight = Captured::default();
    server
        .read_into(Epoch::Plaintext, &client_hello, shard, &mut server_flight)
        .expect("server reads ClientHello");
    total_wire_bytes += server_flight.wire_bytes;

    let server_hello = server_flight.take(Epoch::Plaintext);
    let server_handshake = server_flight.take(Epoch::Handshake);
    assert!(
        !server_handshake.is_empty(),
        "missing server handshake flight"
    );

    let mut client_keys = Captured::default();
    client
        .read_into(Epoch::Plaintext, &server_hello, &mut client_keys)
        .expect("client reads ServerHello");
    total_wire_bytes += client_keys.wire_bytes;

    let mut client_finished = Captured::default();
    client
        .read_into(Epoch::Handshake, &server_handshake, &mut client_finished)
        .expect("client reads encrypted server flight");
    total_wire_bytes += client_finished.wire_bytes;
    assert!(client_finished.done, "client handshake did not complete");
    let resumption_psk = client_finished.psk;
    let client_finished_bytes = client_finished.take(Epoch::Handshake);

    let mut server_finished = Captured::default();
    server
        .read_into(
            Epoch::Handshake,
            &client_finished_bytes,
            shard,
            &mut server_finished,
        )
        .expect("server reads client Finished");
    total_wire_bytes += server_finished.wire_bytes;
    assert!(server_finished.done, "server handshake did not complete");

    let ticket = if server_finished.application.is_empty() {
        None
    } else {
        let new_session_ticket = server_finished.take(Epoch::Application);
        let mut client_ticket = Captured::default();
        client
            .read_into(Epoch::Application, &new_session_ticket, &mut client_ticket)
            .expect("client reads NewSessionTicket");
        total_wire_bytes += client_ticket.wire_bytes;
        let psk = client_ticket
            .psk
            .or(resumption_psk)
            .expect("resumption secret accompanies NewSessionTicket");
        let (age_add, ticket) = client_ticket.ticket.expect("NewSessionTicket event");
        Some(TicketFixture {
            psk,
            ticket,
            age_add,
        })
    };

    black_box(client.into_workspace());
    black_box(server.into_workspace());
    HandshakeOutcome {
        wire_bytes: total_wire_bytes,
        ticket,
    }
}

fn drive_hrr_round_trip(template: &Template, shard: &mut Shard, now_ms: u64) -> usize {
    let mut client = Client::with_prepared_workspace(
        template.clone().without_resumption(),
        None,
        move || now_ms,
        Scratch::for_client(),
    );
    client
        .set_kex_group(KexGroup::Secp256r1)
        .expect("set HRR benchmark's initial P-256 share");
    let mut server = Server::new(
        server::config::Connection {
            transport_params: Vec::new(),
        },
        move || now_ms,
    );

    let mut client_start = Captured::default();
    client
        .start_into(&mut client_start)
        .expect("start HRR benchmark client");
    let client_hello = strip_key_share(&client_start.take(Epoch::Plaintext));

    let mut server_retry = Captured::default();
    server
        .read_into(Epoch::Plaintext, &client_hello, shard, &mut server_retry)
        .expect("server creates HelloRetryRequest");
    assert!(
        server_retry.handshake.is_empty(),
        "expected HRR-only flight"
    );
    let hrr = server_retry.take(Epoch::Plaintext);

    let mut client_retry = Captured::default();
    client
        .read_into(Epoch::Plaintext, &hrr, &mut client_retry)
        .expect("client creates retry ClientHello");
    let second_client_hello = client_retry.take(Epoch::Plaintext);
    assert!(!second_client_hello.is_empty());

    let wire_bytes = client_hello.len() + hrr.len() + second_client_hello.len();
    black_box(client.into_workspace());
    black_box(server.into_workspace());
    wire_bytes
}

fn strip_key_share(encoded: &[u8]) -> Vec<u8> {
    let mut reader = codec::Reader::new(encoded);
    let Frame::ClientHello(mut hello) = Frame::decode(&mut reader).expect("decode ClientHello")
    else {
        panic!("expected ClientHello")
    };
    hello
        .extensions
        .retain(|item| item.ty != extension::Type::KEY_SHARE);
    let mut stripped = Vec::new();
    Frame::ClientHello(hello)
        .encode(&mut stripped)
        .expect("encode key-share-less ClientHello");
    stripped
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55; 32]).expect("benchmark signing key")
}

fn rpk_fixture(with_tickets: bool) -> (Template, Shard) {
    let signing_key = signing_key();
    let expected_pubkey = *signing_key.pubkey().expect("benchmark public key");
    let (template, resumption) = client::config::Config {
        verifier: Verifier::RawPublicKey { expected_pubkey },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
    .try_into_template()
    .expect("benchmark client template");
    assert!(resumption.is_none());
    let shard = Shard::new(server::config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: with_tickets.then(|| Keys::single(TICKET_KEY)),
    });
    (template, shard)
}

struct X509Fixture {
    template: Template,
    shard: Shard,
    now_ms: u64,
}

fn x509_fixture(chain_entries: usize) -> X509Fixture {
    assert!(chain_entries > 0);
    let ca_count = chain_entries;
    let ca_keys: Vec<_> = (0..ca_count)
        .map(|_| KeyPair::generate_for(&PKCS_ED25519).expect("CA key"))
        .collect();
    let ca_params: Vec<_> = (0..ca_count)
        .map(|index| ca_params(&format!("shin benchmark CA {index}")))
        .collect();

    let root_der = ca_params[0]
        .clone()
        .self_signed(&ca_keys[0])
        .expect("root certificate")
        .der()
        .to_vec();
    let mut intermediate_der = Vec::with_capacity(chain_entries.saturating_sub(1));
    for index in 1..ca_count {
        let issuer = Issuer::from_params(&ca_params[index - 1], &ca_keys[index - 1]);
        let certificate = ca_params[index]
            .clone()
            .signed_by(&ca_keys[index], &issuer)
            .expect("intermediate certificate");
        intermediate_der.push(certificate.der().to_vec());
    }

    let leaf_key = KeyPair::generate_for(&PKCS_ED25519).expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec![HOSTNAME.to_owned()]).expect("leaf params");
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOSTNAME);
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_issuer = Issuer::from_params(&ca_params[ca_count - 1], &ca_keys[ca_count - 1]);
    let leaf_der = leaf_params
        .signed_by(&leaf_key, &leaf_issuer)
        .expect("leaf certificate")
        .der()
        .to_vec();
    let leaf_seed = extract_ed25519_seed(&leaf_key.serialize_der()).expect("leaf Ed25519 seed");
    let server_signing_key = SigningKey::from_seed(&leaf_seed).expect("leaf signing key");

    let mut server_chain = Vec::with_capacity(chain_entries);
    server_chain.push(leaf_der.clone());
    server_chain.extend(intermediate_der.into_iter().rev());
    assert_eq!(server_chain.len(), chain_entries);

    let anchor = OwnedTrustAnchor::from_cert_der(&root_der).expect("root trust anchor");
    let now_ms = now_inside(&leaf_der) * 1_000;
    let (template, resumption) = client::config::Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor],
            hostname: HOSTNAME.as_bytes().to_vec(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
    .try_into_template()
    .expect("X.509 benchmark client template");
    assert!(resumption.is_none());
    let shard = Shard::new(server::config::Config {
        source: CertSource::X509 {
            chain_der: server_chain,
            signing_key: server_signing_key,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    X509Fixture {
        template,
        shard,
        now_ms,
    }
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
}

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut outer = Reader::new(pkcs8);
    let sequence = outer.read_tagged(Tag::SEQUENCE).ok()?;
    let mut sequence = Reader::new(sequence);
    sequence.read_tagged(Tag::INTEGER).ok()?;
    sequence.read_tagged(Tag::SEQUENCE).ok()?;
    let private_key = sequence.read_tagged(Tag::OCTET_STRING).ok()?;
    let mut private_key = Reader::new(private_key);
    let seed = private_key.read_tagged(Tag::OCTET_STRING).ok()?;
    let seed: [u8; 32] = seed.try_into().ok()?;
    Some(seed)
}

fn now_inside(cert_der: &[u8]) -> u64 {
    let cert = Cert::parse(cert_der).expect("benchmark certificate parses");
    let not_before = UnixTime::from_time_value(&cert.tbs.validity.not_before)
        .expect("not-before is representable");
    let not_after = UnixTime::from_time_value(&cert.tbs.validity.not_after)
        .expect("not-after is representable");
    (not_before.0 + not_after.0) / 2
}

fn iteration_scale() -> usize {
    std::env::var("SHIN_BENCH_SCALE")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn iterations(base: usize, scale: usize) -> usize {
    base.checked_mul(scale)
        .expect("SHIN_BENCH_SCALE makes iteration count overflow")
}

fn measure(
    name: &str,
    iterations: usize,
    payload_bytes: Option<usize>,
    mut operation: impl FnMut() -> usize,
) {
    let warmup = (iterations / 20).clamp(1, 10);
    for _ in 0..warmup {
        black_box(operation());
    }

    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        checksum ^= black_box(operation());
    }
    let elapsed = started.elapsed();
    black_box(checksum);

    let nanos_per_op = elapsed.as_nanos() as f64 / iterations as f64;
    let operations_per_second = iterations as f64 / elapsed.as_secs_f64();
    let throughput =
        payload_bytes.map(|bytes| operations_per_second * bytes as f64 / (1024.0 * 1024.0));
    match throughput {
        Some(mib_per_second) => println!(
            "{name:<38} {iterations:>8} {nanos_per_op:>14.1} {operations_per_second:>14.1} {mib_per_second:>12.1}",
        ),
        None => println!(
            "{name:<38} {iterations:>8} {nanos_per_op:>14.1} {operations_per_second:>14.1} {:>12}",
            "-",
        ),
    }
}

fn print_layout_profile() {
    type BenchClock = fn() -> u64;

    let client_scratch = Scratch::for_client();
    let server_scratch = Scratch::for_server();
    println!(
        "layout_bytes\tClient<fn clock>\t{}",
        size_of::<Client<BenchClock>>()
    );
    println!(
        "layout_bytes\tServer<fn clock>\t{}",
        size_of::<Server<BenchClock>>()
    );
    println!("layout_bytes\tShard\t{}", size_of::<Shard>());
    println!("layout_bytes\tScratch\t{}", size_of::<Scratch>());
    println!("layout_bytes\tEphemeralKey\t{}", size_of::<EphemeralKey>());
    println!("layout_bytes\tSharedSecret\t{}", size_of::<SharedSecret>());
    println!(
        "scratch_limits\tclient\treassembly={}\tflight={}\tidentity={}",
        client_scratch.capacities().0,
        client_scratch.capacities().1,
        client_scratch.capacities().2,
    );
    println!(
        "scratch_limits\tserver\treassembly={}\tflight={}\tidentity={}",
        server_scratch.capacities().0,
        server_scratch.capacities().1,
        server_scratch.capacities().2,
    );
    println!(
        "scratch_default_heap\tclient\tallocations=2\treserved_bytes={}",
        2 * shin::wire::record::MAX_PLAINTEXT_BODY,
    );
    println!(
        "scratch_default_heap\tserver\tallocations=2\treserved_bytes={}",
        2 * shin::wire::record::MAX_PLAINTEXT_BODY,
    );
}

fn benchmark_handshakes(scale: usize) {
    let (full_template, mut full_shard) = rpk_fixture(false);
    let full_sample = drive_handshake(
        &full_template,
        None,
        &mut full_shard,
        KexGroup::X25519,
        1_000_000,
    );
    println!(
        "sample_wire_bytes\tfull/rpk-x25519\t{}",
        full_sample.wire_bytes
    );
    measure(
        "handshake/full-rpk-x25519",
        iterations(200, scale),
        None,
        || {
            drive_handshake(
                &full_template,
                None,
                &mut full_shard,
                KexGroup::X25519,
                1_000_000,
            )
            .wire_bytes
        },
    );

    let (resumption_template, mut resumption_shard) = rpk_fixture(true);
    let issued = drive_handshake(
        &resumption_template,
        None,
        &mut resumption_shard,
        KexGroup::X25519,
        1_000_000,
    )
    .ticket
    .expect("ticket-enabled handshake issues a ticket");
    let resumed_sample = drive_handshake(
        &resumption_template,
        Some(issued.resumption()),
        &mut resumption_shard,
        KexGroup::X25519,
        1_000_000,
    );
    println!(
        "sample_wire_bytes\tresumption/rpk-x25519\t{}",
        resumed_sample.wire_bytes,
    );
    measure(
        "handshake/resumption-rpk-x25519",
        iterations(400, scale),
        None,
        || {
            drive_handshake(
                &resumption_template,
                Some(issued.resumption()),
                &mut resumption_shard,
                KexGroup::X25519,
                1_000_000,
            )
            .wire_bytes
        },
    );

    let (hrr_template, mut hrr_shard) = rpk_fixture(false);
    let hrr_sample = drive_hrr_round_trip(&hrr_template, &mut hrr_shard, 1_000_000);
    println!("sample_wire_bytes\thrr/round-trip\t{hrr_sample}");
    measure(
        "handshake/hrr-round-trip",
        iterations(100, scale),
        None,
        || drive_hrr_round_trip(&hrr_template, &mut hrr_shard, 1_000_000),
    );

    for chain_entries in [1, 2, 4] {
        let mut fixture = x509_fixture(chain_entries);
        let sample = drive_handshake(
            &fixture.template,
            None,
            &mut fixture.shard,
            KexGroup::X25519,
            fixture.now_ms,
        );
        println!(
            "sample_wire_bytes\tx509-chain-{chain_entries}\t{}",
            sample.wire_bytes,
        );
        let name = format!("handshake/x509-chain-{chain_entries}");
        measure(&name, iterations(50, scale), None, || {
            drive_handshake(
                &fixture.template,
                None,
                &mut fixture.shard,
                KexGroup::X25519,
                fixture.now_ms,
            )
            .wire_bytes
        });
    }
}

fn benchmark_records(scale: usize) {
    for payload_len in [0, 64, 1_024, 16_384] {
        let payload = vec![0x5A; payload_len];
        let mut sealer = Sealer::from_secret(&TRAFFIC_SECRET).expect("record sealer");
        let mut opener = Opener::from_secret(&TRAFFIC_SECRET).expect("record opener");
        let name = format!("record/seal-open-{payload_len}");
        measure(&name, iterations(10_000, scale), Some(payload_len), || {
            let mut wire = sealer
                .seal(ContentType::ApplicationData, black_box(&payload))
                .expect("seal benchmark record");
            let (_, plaintext, consumed) = opener
                .open(black_box(&mut wire))
                .expect("open benchmark record")
                .expect("complete benchmark record");
            assert_eq!(plaintext.len(), payload_len);
            consumed
        });
    }
}

fn benchmark_kx(scale: usize) {
    let rng = SystemRandom::new();
    for (group, base_iterations) in [
        (KexGroup::X25519, 2_000),
        (KexGroup::Secp256r1, 1_000),
        (KexGroup::X25519Mlkem768, 50),
    ] {
        let name = format!("kx/{group:?}-round-trip");
        measure(&name, iterations(base_iterations, scale), None, || {
            let client = EphemeralKey::generate(group, &rng).expect("client KX generation");
            let (server_share, server_secret) = group
                .respond(client.client_share(), &rng)
                .expect("server KX response");
            let client_secret = client.agree(&server_share).expect("client KX agreement");
            assert_eq!(client_secret.as_slice(), server_secret.as_slice());
            client_secret.as_slice().len() + server_share.len()
        });
    }
}

fn main() {
    let scale = iteration_scale();
    println!("shin perf ceiling (release profile, descriptive only)");
    println!("SHIN_BENCH_SCALE={scale}");
    print_layout_profile();
    println!();
    println!(
        "{:<38} {:>8} {:>14} {:>14} {:>12}",
        "benchmark", "iters", "ns/op", "ops/s", "MiB/s",
    );
    benchmark_handshakes(scale);
    benchmark_records(scale);
    benchmark_kx(scale);
}
