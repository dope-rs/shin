use crate::connection;
use crate::transport;
use crate::wire::protocols;
use alloc::rc;
use alloc::vec;
use core::mem;

mod error;
mod identity;
mod owned;
mod restore;
pub(crate) mod resumption;
mod ticket;
mod truststore;
mod verifier;

pub use error::Error;
pub use identity::Identity;
pub use identity::template::IdentityTemplate;
pub use owned::trust::anchor::OwnedTrustAnchor;
pub use restore::Restore;
pub use restore::alpn::NegotiatedAlpn;
pub use resumption::Resumption;
pub use ticket::Ticket;
pub use truststore::TrustStore;
pub use verifier::{CertificateLimit, Verifier};

pub const MAX_TRUST_ANCHORS: usize = 256;

pub struct Config {
    pub verifier: Verifier,
    pub transport_params: vec::Vec<u8>,
    pub alpn_protocols: vec::Vec<vec::Vec<u8>>,
    pub enable_early_data: bool,
}

/// Immutable, cheaply cloned endpoint policy shared by connections.
#[derive(Clone)]
pub struct Template {
    inner: rc::Rc<Shared>,
}

/// A validated template plus connection-local resumption state.
/// Construction proves the pair fits the initial TLS record.
pub struct Prepared {
    pub(super) template: Template,
    pub(super) resumption: Option<resumption::Active>,
    pub(super) enable_early_data: bool,
}

struct Shared {
    verifier: Verifier,
    transport_mode: transport::Mode,
    transport_params: vec::Vec<u8>,
    alpn_protocols: protocols::PreparedAlpn,
    enable_early_data: bool,
}

const _: () = assert!(mem::size_of::<Template>() == mem::size_of::<usize>());

impl Config {
    /// Reject unusable trust, identity, or wire-length settings before the
    /// handshake starts in TLS-over-stream mode.
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_with_transport(transport::Mode::Tls)
    }

    /// Reject unusable settings for the explicitly selected transport.
    pub fn validate_with_transport(&self, transport_mode: transport::Mode) -> Result<(), Error> {
        match &self.verifier {
            Verifier::X509 {
                anchors, hostname, ..
            } => {
                if anchors.is_empty() {
                    return Err(Error::MissingTrustAnchors);
                }
                if anchors.len() > MAX_TRUST_ANCHORS {
                    return Err(Error::TooManyTrustAnchors {
                        count: anchors.len(),
                        maximum: MAX_TRUST_ANCHORS,
                    });
                }
                for (index, anchor) in anchors.iter().enumerate() {
                    if anchor.view().is_err() {
                        return Err(Error::MalformedTrustAnchor { index });
                    }
                }
                validate_hostname(hostname)?;
            }
            Verifier::X509Store {
                roots, hostname, ..
            } => {
                debug_assert!(!roots.is_empty());
                validate_hostname(hostname)?;
            }
            Verifier::RawPublicKey { .. } => {}
        }
        if self.transport_params.len() > u16::MAX as usize {
            return Err(Error::TransportParametersTooLong {
                len: self.transport_params.len(),
                maximum: u16::MAX as usize,
            });
        }
        if transport_mode.is_tls() && !self.transport_params.is_empty() {
            return Err(Error::TransportParametersInTls {
                len: self.transport_params.len(),
            });
        }
        let mut alpn_total = 0usize;
        for (index, protocol) in self.alpn_protocols.iter().enumerate() {
            if protocol.is_empty() {
                return Err(Error::EmptyAlpnProtocol { index });
            }
            if protocol.len() > u8::MAX as usize {
                return Err(Error::AlpnProtocolTooLong {
                    index,
                    len: protocol.len(),
                    maximum: u8::MAX as usize,
                });
            }
            alpn_total = alpn_total
                .checked_add(1 + protocol.len())
                .ok_or(Error::ClientHelloEncodingOverflow)?;
        }
        if alpn_total > u16::MAX as usize {
            return Err(Error::AlpnListTooLong {
                len: alpn_total,
                maximum: u16::MAX as usize,
            });
        }
        validate_initial_hello(
            transport_mode,
            &self.verifier,
            &self.transport_params,
            &self.alpn_protocols,
            None,
        )?;
        Ok(())
    }

    /// Validates reusable endpoint policy once in TLS-over-stream mode.
    pub fn try_into_template(self) -> Result<Template, Error> {
        self.try_into_template_with_transport(transport::Mode::Tls)
    }

    /// Validates reusable endpoint policy for an explicit transport.
    pub fn try_into_template_with_transport(
        mut self,
        transport_mode: transport::Mode,
    ) -> Result<Template, Error> {
        self.verifier = self.verifier.prepare()?;
        self.validate_with_transport(transport_mode)?;
        self.into_template(transport_mode)
    }

    /// Validates the exact first-connection configuration once in
    /// TLS-over-stream mode.
    pub fn try_into_prepared(self) -> Result<Prepared, Error> {
        self.try_into_prepared_with_transport(transport::Mode::Tls)
    }

    /// Validates the exact first-connection configuration for an explicit
    /// transport.
    pub fn try_into_prepared_with_transport(
        self,
        transport_mode: transport::Mode,
    ) -> Result<Prepared, Error> {
        Ok(self
            .try_into_template_with_transport(transport_mode)?
            .without_resumption())
    }

    fn into_template(self, transport_mode: transport::Mode) -> Result<Template, Error> {
        let inner = Shared {
            verifier: self.verifier,
            transport_mode,
            transport_params: self.transport_params,
            alpn_protocols: protocols::PreparedAlpn::prepare(self.alpn_protocols)
                .map_err(|()| Error::ClientHelloEncodingOverflow)?,
            enable_early_data: self.enable_early_data,
        };
        Ok(Template {
            inner: rc::Rc::new(inner),
        })
    }
}

fn validate_hostname(hostname: &[u8]) -> Result<(), Error> {
    use crate::identity::Hostname;
    if hostname.is_empty() {
        return Err(Error::MissingServerName);
    }
    if !Hostname::new(hostname).is_valid_reference() {
        return Err(Error::InvalidServerName);
    }
    Ok(())
}

impl Template {
    /// Returns the exact reusable workspace plan for this endpoint policy.
    pub fn workspace_layout(&self, identity: Option<&IdentityTemplate>) -> super::WorkspaceLayout {
        super::WorkspaceLayout::prepared(
            self.inner.verifier.certificate_limit().get(),
            identity.map_or(0, IdentityTemplate::outbound_flight_capacity),
        )
    }

    /// Resolves persisted endpoint metadata once, then moves only compact,
    /// validated resumption state into the handshake.
    pub fn restore(self, restore: Restore<'_>) -> Result<Prepared, Error> {
        let resumption = restore.bind(&self);
        validate_initial_hello(
            self.inner.transport_mode,
            &self.inner.verifier,
            &self.inner.transport_params,
            self.inner.alpn_protocols.preferred(),
            Some(&resumption),
        )?;
        Ok(Prepared {
            enable_early_data: self.inner.enable_early_data,
            template: self,
            resumption: Some(resumption),
        })
    }

    /// Removing resumption can only reduce a previously validated ClientHello.
    pub fn without_resumption(self) -> Prepared {
        Prepared {
            enable_early_data: self.inner.enable_early_data,
            template: self,
            resumption: None,
        }
    }

    pub(crate) fn verifier(&self) -> &Verifier {
        &self.inner.verifier
    }

    pub fn transport_mode(&self) -> transport::Mode {
        self.inner.transport_mode
    }

    pub(crate) fn transport_params(&self) -> &[u8] {
        &self.inner.transport_params
    }

    pub(crate) fn alpn_protocols(&self) -> &[vec::Vec<u8>] {
        self.inner.alpn_protocols.preferred()
    }

    pub(crate) fn find_alpn(&self, protocol: &[u8]) -> Option<protocols::AlpnId> {
        self.inner.alpn_protocols.find(protocol)
    }

    pub(crate) fn alpn(&self, id: protocols::AlpnId) -> Option<&[u8]> {
        self.inner.alpn_protocols.get(id)
    }
}

impl Prepared {
    /// Returns the exact workspace plan for this prepared connection.
    pub fn workspace_layout(&self, identity: Option<&IdentityTemplate>) -> super::WorkspaceLayout {
        self.template.workspace_layout(identity)
    }

    /// Returns the validated reusable policy without exposing resumption state.
    pub fn template(&self) -> Template {
        self.template.clone()
    }

    /// Admits caller-owned storage before creating a client.
    pub fn try_into_client_with_workspace<C: connection::Clock>(
        self,
        identity: Option<IdentityTemplate>,
        clock: C,
        storage: super::Workspace,
    ) -> Result<super::Client<C>, super::WorkspaceRejection> {
        let layout = self.workspace_layout(identity.as_ref());
        let storage = layout.admit(storage)?;
        Ok(self.build_client(identity, clock, storage))
    }

    pub(in crate::client) fn build_client<C: connection::Clock>(
        self,
        identity: Option<IdentityTemplate>,
        clock: C,
        storage: super::Workspace,
    ) -> super::Client<C> {
        use crate::client::session;
        use crate::client::state;
        use crate::crypto::hash::Transcript;
        use crate::crypto::kx;
        use crate::crypto::material;
        use crate::memory::threadbound::ThreadBound;
        use crate::wire::handshake;
        use crate::wire::handshake::reassemblers::HsReassembler;
        use crate::wire::record;
        use o3::collections::fixed::array;
        use ring::rand::SystemRandom;
        use session::Application;
        use session::Buffers;
        use session::Credentials;
        use session::Extensions;
        use session::Handshake;
        use session::OfferSettings;
        use session::Runtime;
        let Self {
            template: config,
            resumption,
            enable_early_data,
        } = self;
        let super::Workspace { reassembly, flight } = storage;
        super::Client {
            session: session::Session {
                offer: OfferSettings {
                    config,
                    enable_early_data,
                    kex_group: kx::KexGroup::X25519,
                    offered_suites: array::CopyInline::from_array(record::CipherSuite::SUPPORTED),
                },
                handshake: Handshake {
                    state: state::State::initial(),
                    transcript: Transcript::new(),
                    client_random: [0u8; handshake::RANDOM_LEN],
                    session_id: [0; 32],
                    hrr_done: false,
                    resumption,
                    psk_used: false,
                },
                kx: kx::Owned::new(),
                extensions: Extensions {
                    selected_alpn: None,
                    early_data: session::EarlyData::NotOffered,
                },
                credentials: Credentials {
                    identity,
                    certificate_response: None,
                },
                application: Application {
                    traffic: material::State::default(),
                    resumption_master: None,
                    exporter_master: None,
                },
                buffers: Buffers {
                    reasm: HsReassembler::with_buffer(reassembly),
                    flight,
                },
                runtime: Runtime {
                    clock,
                    rng: SystemRandom::new(),
                    _thread: ThreadBound::NEW,
                },
            },
        }
    }

    pub(crate) fn from_retained(
        resumption: Resumption,
        enable_early_data: bool,
    ) -> Result<Self, Error> {
        let (template, resumption) = resumption.into_parts();
        validate_initial_hello(
            template.inner.transport_mode,
            &template.inner.verifier,
            &template.inner.transport_params,
            template.inner.alpn_protocols.preferred(),
            Some(&resumption),
        )?;
        Ok(Self {
            template,
            resumption: Some(resumption),
            enable_early_data,
        })
    }
}

fn validate_initial_hello(
    transport_mode: transport::Mode,
    verifier: &Verifier,
    transport_params: &[u8],
    alpn_protocols: &[vec::Vec<u8>],
    resumption: Option<&resumption::Active>,
) -> Result<(), Error> {
    use crate::client::offer::Offer;
    use crate::wire::record::MAX_PLAINTEXT_BODY;
    let len = Offer::maximum_initial_len(
        transport_mode,
        verifier,
        transport_params,
        alpn_protocols,
        resumption,
    )
    .map_err(|_| Error::ClientHelloEncodingOverflow)?;
    if len > MAX_PLAINTEXT_BODY {
        return Err(Error::ClientHelloTooLarge {
            len,
            maximum: MAX_PLAINTEXT_BODY,
        });
    }
    Ok(())
}
