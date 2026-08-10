use crate::connection;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::server;
use crate::server::config;

/// Per-core prepared server policy and replay guard.
pub struct Shard<
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
> {
    pub(super) policy: Policy<G, V>,
    pub(super) prepared: Prepared,
    _thread: threadbound::ThreadBound,
}

pub(super) struct Policy<G, V> {
    pub(super) config: config::Config,
    pub(super) guard: G,
    pub(super) client_auth: Option<config::ClientAuth>,
    pub(super) verifier: V,
}

pub(super) struct Prepared {
    pub(super) identity: ShardIdentity,
    pub(super) replay_domain: server::ReplayDomain,
    pub(super) flight: Option<config::FlightProfile>,
    pub(super) error: Option<connection::Error>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ShardIdentity(pub(super) u64);

impl ShardIdentity {
    fn try_new() -> Result<Self, connection::Error> {
        use core::sync::atomic::AtomicU64;
        use core::sync::atomic::Ordering;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map(Self)
        .map_err(|_| connection::Error::BadConfig)
    }
}

impl Shard<config::NoGuard, config::NoClientAuth> {
    /// Builds a fully validated Shard prepared for connection preflight.
    pub fn try_new(config: config::Config) -> Result<Self, connection::Error> {
        Self::try_build(config, config::NoGuard, None, config::NoClientAuth, None)
    }

    /// Caches invalid policy for a `BadConfig` on the first drive.
    pub fn new(config: config::Config) -> Self {
        Self::build(config, config::NoGuard, None, config::NoClientAuth, None)
    }
}

impl<G: config::EarlyDataGuard> Shard<G, config::NoClientAuth> {
    pub fn try_with_early_data_guard(
        config: config::Config,
        guard: G,
    ) -> Result<Self, connection::Error> {
        Self::try_build(config, guard, None, config::NoClientAuth, None)
    }

    pub fn with_early_data_guard(config: config::Config, guard: G) -> Self {
        Self::build(config, guard, None, config::NoClientAuth, None)
    }

    pub fn try_with_early_data_guard_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
    ) -> Result<Self, connection::Error> {
        Self::try_build(
            config,
            guard,
            None,
            config::NoClientAuth,
            Some(replay_domain),
        )
    }

    /// Shares a domain only when the guard shares its atomic replay store.
    pub fn with_early_data_guard_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
    ) -> Self {
        Self::build(
            config,
            guard,
            None,
            config::NoClientAuth,
            Some(replay_domain),
        )
    }
}

impl<V: config::ClientCertVerifier> Shard<config::NoGuard, V> {
    pub fn try_with_client_auth(
        config: config::Config,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        Self::try_build(config, config::NoGuard, Some(mode), verifier, None)
    }

    pub fn with_client_auth(config: config::Config, mode: config::ClientAuth, verifier: V) -> Self {
        Self::build(config, config::NoGuard, Some(mode), verifier, None)
    }
}

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier> Shard<G, V> {
    pub fn try_with_early_data_guard_and_client_auth(
        config: config::Config,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        Self::try_build(config, guard, Some(mode), verifier, None)
    }

    pub fn with_early_data_guard_and_client_auth(
        config: config::Config,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Self {
        Self::build(config, guard, Some(mode), verifier, None)
    }

    pub fn try_with_early_data_guard_and_client_auth_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        Self::try_build(config, guard, Some(mode), verifier, Some(replay_domain))
    }

    /// Shares a domain only when the guard shares its atomic replay store.
    pub fn with_early_data_guard_and_client_auth_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Self {
        Self::build(config, guard, Some(mode), verifier, Some(replay_domain))
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<ticket::Keys>) {
        self.policy.config.ticket_keys = keys;
    }

    fn try_build(
        config: config::Config,
        guard: G,
        client_auth: Option<config::ClientAuth>,
        verifier: V,
        replay_domain: Option<server::ReplayDomain>,
    ) -> Result<Self, connection::Error> {
        let flight = config.prepare_for(client_auth.is_some(), G::ACCEPTS_EARLY_DATA)?;
        Ok(Self {
            policy: Policy {
                config,
                guard,
                client_auth,
                verifier,
            },
            prepared: Prepared {
                identity: ShardIdentity::try_new()?,
                replay_domain: match replay_domain {
                    Some(replay_domain) => replay_domain,
                    None => server::ReplayDomain::random()?,
                },
                flight: Some(flight),
                error: None,
            },
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    fn build(
        config: config::Config,
        guard: G,
        client_auth: Option<config::ClientAuth>,
        verifier: V,
        replay_domain: Option<server::ReplayDomain>,
    ) -> Self {
        let prepared = config.prepare_for(client_auth.is_some(), G::ACCEPTS_EARLY_DATA);
        let (flight, mut error) = match prepared {
            Ok(profile) => (Some(profile), None),
            Err(cause) => (None, Some(cause)),
        };
        let identity = match ShardIdentity::try_new() {
            Ok(identity) => identity,
            Err(cause) => {
                error = Some(cause);
                ShardIdentity(0)
            }
        };
        let replay_domain = replay_domain.unwrap_or_else(|| match server::ReplayDomain::random() {
            Ok(domain) => domain,
            Err(cause) => {
                error = Some(cause);
                server::ReplayDomain([0; ticket::REPLAY_DOMAIN_LEN])
            }
        });
        Self {
            policy: Policy {
                config,
                guard,
                client_auth,
                verifier,
            },
            prepared: Prepared {
                identity,
                replay_domain,
                flight,
                error,
            },
            _thread: threadbound::ThreadBound::NEW,
        }
    }
}
