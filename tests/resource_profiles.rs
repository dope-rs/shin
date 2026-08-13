use core::hint::black_box;
use core::mem::size_of;

use ring::rand::SystemRandom;
use shin::client;
use shin::client::config::{Config, NegotiatedAlpn, Restore, Resumption, Verifier};
use shin::client::{Client, Hybrid, Ticket};
use shin::crypto::kx::{EphemeralKey, HybridWorkspace, KexGroup};
use shin::crypto::ticket;
use shin::server::config::{ClientAuthVerifier, NoClientAuth};
use shin::server::workspace::{Profile, Workspace};
use shin::server::{
    Binding, MultiplexedConnection, PooledConnection, PreparedShard, Rejection, Server, Shard,
};
use shin::transport::Mode;
use shin::wire::handshake::storage::Scratch;
use shin::wire::record::{CipherSuite, MAX_PLAINTEXT_BODY};

mod support;

use support::AllocationProbe;

#[test]
fn default_workspaces_reserve_one_record_not_the_handshake_limit() {
    use shin::crypto::sig::SigningKey;
    use shin::server::config::{CertSource, ClientAuth};

    type TestClock = fn() -> u64;

    fn config(seed: u8) -> shin::server::config::Config {
        shin::server::config::Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[seed; 32]).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        }
    }

    let standard = Shard::new(config(7)).unwrap();
    let mutual = Shard::with_client_auth(config(8), ClientAuth::Requested, NoClientAuth).unwrap();
    let client_layout = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [7; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
    .try_into_template()
    .unwrap()
    .workspace_layout(None);

    let mut client = None;
    let client_profile = AllocationProbe::measured_with_bytes(|| {
        client = Some(client_layout.allocate());
    });
    let mut server = None;
    let server_profile = AllocationProbe::measured_with_bytes(|| {
        server = Some(standard.tls_workspace_layout().allocate());
    });
    let mut mutual_server = None;
    let mutual_server_profile = AllocationProbe::measured_with_bytes(|| {
        mutual_server = Some(mutual.tls_workspace_layout().allocate());
    });
    let client = client.unwrap();

    assert_eq!(
        client.capacities(),
        (MAX_PLAINTEXT_BODY, MAX_PLAINTEXT_BODY)
    );
    assert_eq!(client_profile, (2, 32 * 1024));
    assert_eq!(server_profile, (2, 32 * 1024));
    assert_eq!(mutual_server_profile, (3, 48 * 1024));
    assert_eq!(size_of::<Scratch>(), 144);
    assert_eq!(size_of::<client::workspace::Workspace>(), 96);
    assert_eq!(size_of::<Workspace>(), size_of::<Scratch>());
    assert_eq!(size_of::<Profile>(), 4 * size_of::<usize>());
    assert_eq!(
        size_of::<Binding<u8, [u8; 1_024]>>(),
        size_of::<Result<u8, Rejection<[u8; 1_024]>>>()
    );
    assert_eq!(
        size_of::<Workspace<ClientAuthVerifier<NoClientAuth>>>(),
        size_of::<Scratch>(),
    );
    assert_eq!(size_of::<Client<TestClock>>(), 1_336);
    assert_eq!(
        size_of::<shin::client::PooledConnection<'static, TestClock>>(),
        2 * size_of::<usize>(),
    );
    assert_eq!(size_of::<Server<TestClock>>(), 1_048);
    assert_eq!(size_of::<PreparedShard>(), size_of::<usize>());
    assert_eq!(size_of::<Shard>(), size_of::<usize>());
    assert_eq!(
        size_of::<MultiplexedConnection<TestClock>>(),
        size_of::<Server<TestClock>>() + size_of::<usize>(),
    );
    assert_eq!(
        size_of::<PooledConnection<'static, TestClock>>(),
        2 * size_of::<usize>(),
    );
    assert_eq!(
        size_of::<PooledConnection<'static, TestClock, 0, ClientAuthVerifier<NoClientAuth>>>(),
        size_of::<PooledConnection<'static, TestClock>>(),
    );
    black_box((server, mutual_server));
}

#[test]
fn multiplexed_server_admission_is_allocation_free() {
    use shin::crypto::sig::SigningKey;
    use shin::server::config::{CertSource, Connection};

    fn now() -> u64 {
        0
    }

    let shard = Shard::new(shin::server::config::Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
        },
        alpn_protocols: vec![b"h2".to_vec()],
        ticket_keys: None,
    })
    .unwrap();
    let server = Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        now as fn() -> u64,
    )
    .unwrap();
    let allocations = AllocationProbe::measured(|| {
        black_box(shard.bind_multiplexed(server).into_result().unwrap());
    });
    assert_eq!(allocations, 0);

    let pool = shard
        .tls_profile()
        .into_pool::<fn() -> u64>(o3::collections::slab::Capacity::try_from(1).unwrap());
    let allocations = AllocationProbe::measured(|| {
        black_box(pool.connect(now as fn() -> u64).unwrap());
    });
    assert_eq!(allocations, 0);
}

#[test]
fn one_time_domain_binding_preserves_borrows_without_allocation() {
    use core::cell::Cell;

    use shin::crypto::sig::SigningKey;
    use shin::server::config::{CertSource, EarlyDataGuard};

    struct BorrowedGuard<'a>(&'a Cell<usize>);

    impl EarlyDataGuard for BorrowedGuard<'_> {
        fn register(&self, _token: &[u8]) -> bool {
            self.0.set(self.0.get() + 1);
            true
        }
    }

    let registrations = Cell::new(0);
    let prepared = PreparedShard::with_early_data_guard(
        shin::server::config::Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        BorrowedGuard(&registrations),
    )
    .unwrap();

    let mut shard = None;
    let allocations = AllocationProbe::measured(|| {
        shard = Some(prepared.bind_domain::<7>());
    });

    assert_eq!(allocations, 0);
    let shard = shard.unwrap();
    let pool = shard
        .tls_profile()
        .into_pool::<fn() -> u64>(o3::collections::slab::Capacity::try_from(1).unwrap());
    let connection = pool.connect((|| 0) as fn() -> u64).unwrap();
    drop(connection);
    drop(pool);
    drop(shard);
    assert_eq!(registrations.get(), 0);
}

#[test]
fn mutual_workspace_profile_survives_recycling_without_allocation() {
    use shin::crypto::sig::SigningKey;
    use shin::server::config::{CertSource, ClientAuth};

    fn now() -> u64 {
        0
    }

    let shard = Shard::with_client_auth(
        shin::server::config::Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Requested,
        NoClientAuth,
    )
    .unwrap();
    let pool = shard
        .tls_profile()
        .into_pool::<fn() -> u64>(o3::collections::slab::Capacity::try_from(1).unwrap());

    let allocations = AllocationProbe::measured(|| {
        for _ in 0..128 {
            let connection = pool.connect(now as fn() -> u64).unwrap();
            black_box(&connection);
            drop(connection);
        }
    });

    assert_eq!(allocations, 0);
    black_box(pool);
}

#[test]
fn shard_profile_selects_the_exact_connection_reservations() {
    use shin::crypto::sig::SigningKey;
    use shin::server::config::{CertSource, ClientAuth, Connection};

    fn shard_config(seed: u8) -> shin::server::config::Config {
        shin::server::config::Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[seed; 32]).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        }
    }

    fn now() -> u64 {
        0
    }

    let standard = Shard::new(shard_config(7)).unwrap();
    let mutual =
        Shard::with_client_auth(shard_config(8), ClientAuth::Requested, NoClientAuth).unwrap();
    let mut standard_connection = None;
    let standard_profile = AllocationProbe::measured_with_bytes(|| {
        standard_connection = Some(
            standard
                .new_multiplexed(
                    Connection {
                        transport_params: Vec::new(),
                    },
                    Mode::Tls,
                    now as fn() -> u64,
                )
                .unwrap(),
        );
    });
    let mut mutual_connection = None;
    let mutual_profile = AllocationProbe::measured_with_bytes(|| {
        mutual_connection = Some(
            mutual
                .new_multiplexed(
                    Connection {
                        transport_params: Vec::new(),
                    },
                    Mode::Tls,
                    now as fn() -> u64,
                )
                .unwrap(),
        );
    });

    assert_eq!(standard_profile, (2, 32 * 1024));
    assert_eq!(mutual_profile, (3, 48 * 1024));
    black_box((standard_connection, mutual_connection));
}

#[test]
fn verifier_bound_shapes_mutual_identity_storage_once() {
    use shin::crypto::sig::SigningKey;
    use shin::server::config::{
        CertSource, ClientAuth, ClientCertVerifier, ClientIdentity, Connection,
    };

    struct LargeIdentity;

    impl ClientCertVerifier for LargeIdentity {
        const MAX_CERTIFICATE_MESSAGE_SIZE: usize = 64 * 1024;

        fn verify(&self, _: &ClientIdentity<'_>) -> bool {
            true
        }
    }

    let shard = Shard::with_client_auth(
        shin::server::config::Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[9; 32]).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        LargeIdentity,
    )
    .unwrap();
    let layout = shard.tls_workspace_layout();

    assert_eq!(
        layout.capacities(),
        (64 * 1024, MAX_PLAINTEXT_BODY, 64 * 1024)
    );
    let allocations = AllocationProbe::measured_with_bytes(|| {
        black_box(layout.allocate());
    });
    assert_eq!(allocations, (3, 144 * 1024));

    let undersized = Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
    )
    .unwrap();
    let Err(rejection) = shard.bind_multiplexed(undersized).into_result() else {
        panic!("undersized server was admitted");
    };
    assert_eq!(rejection.error(), &shin::connection::Error::BadConfig);
}

#[test]
fn shard_identity_is_allocated_once_at_construction() {
    use shin::crypto::sig::SigningKey;
    use shin::server::config;
    use shin::server::config::CertSource;

    let signing_key = SigningKey::from_seed(&[7; 32]).unwrap();
    let mut shard = None;
    let allocations = AllocationProbe::measured(|| {
        shard = Some(
            Shard::new(config::Config {
                source: CertSource::RawPublicKey { signing_key },
                alpn_protocols: Vec::new(),
                ticket_keys: None,
            })
            .unwrap(),
        );
    });

    assert_eq!(allocations, 1);
    black_box(shard);
}

#[test]
fn resumption_state_stays_pointer_scale() {
    assert!(size_of::<Ticket<'static>>() <= 128);
    assert!(size_of::<Resumption>() <= 128);
}

#[test]
fn owned_restore_binds_alpn_without_allocating() {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0x42; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"h2".to_vec()],
        enable_early_data: true,
    }
    .try_into_template()
    .unwrap();
    let restore = Restore::try_new([0x77; 32], vec![0xAA; 64], 7, 0, 7_200)
        .unwrap()
        .try_with_early_data(
            16_384,
            CipherSuite::Aes128GcmSha256,
            Mode::Tls,
            NegotiatedAlpn::Protocol(Vec::from(&b"h2"[..]).into()),
        )
        .unwrap();

    let mut prepared = None;
    let allocations = AllocationProbe::measured(|| {
        prepared = Some(template.restore(restore).unwrap());
    });
    assert_eq!(allocations, 0);
    black_box(prepared);
}

#[test]
fn classical_ephemeral_state_is_small_and_allocation_free() {
    assert_eq!(size_of::<EphemeralKey>(), 144);

    let rng = SystemRandom::new();
    let allocations = AllocationProbe::measured(|| {
        let key = EphemeralKey::generate(KexGroup::X25519, &rng).unwrap();
        assert_eq!(key.client_share().len(), 32);
        black_box(key);
    });
    assert_eq!(allocations, 0);
}

#[test]
fn compatibility_hybrid_ephemeral_state_pays_one_explicit_allocation() {
    let rng = SystemRandom::new();
    let allocations = AllocationProbe::measured(|| {
        let key = EphemeralKey::generate(KexGroup::X25519Mlkem768, &rng).unwrap();
        assert_eq!(key.client_share().len(), 1_216);
        black_box(key);
    });
    assert_eq!(allocations, 1);
}

#[test]
fn hybrid_workspace_is_inline_and_charged_only_to_opt_in_clients() {
    type TestClock = fn() -> u64;

    let allocations = AllocationProbe::measured(|| {
        black_box(HybridWorkspace::new());
    });
    assert_eq!(allocations, 0);

    assert_eq!(size_of::<HybridWorkspace>(), 3_272);
    assert_eq!(size_of::<Hybrid<'static, TestClock>>(), 1_200);
}

#[test]
fn ticket_key_schedule_is_allocated_once_and_reused() {
    assert_eq!(size_of::<ticket::Secret>(), size_of::<usize>());

    let mut secret = None;
    let allocations = AllocationProbe::measured(|| {
        secret = Some(ticket::Secret::new([0x42; 32]).unwrap());
    });
    assert_eq!(allocations, 1);
    let secret = secret.unwrap();
    assert_eq!(
        AllocationProbe::measured(|| {
            black_box(secret.clone());
        }),
        0
    );

    let rng = SystemRandom::new();
    let mut encrypted = None;
    let allocations = AllocationProbe::measured(|| {
        encrypted = Some(
            secret
                .encrypt(
                    &[0x24; 32],
                    7,
                    11,
                    CipherSuite::Aes128GcmSha256,
                    b"h3",
                    &rng,
                )
                .unwrap(),
        );
    });
    assert_eq!(allocations, 0);
    let encrypted = encrypted.unwrap();

    let allocations = AllocationProbe::measured(|| {
        black_box(secret.decrypt(&encrypted).unwrap());
    });
    assert_eq!(allocations, 0);
}
