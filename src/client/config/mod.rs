use crate::client::{self, workspace};
use crate::connection;
use crate::crypto::sig;
use crate::transport;
use crate::wire::{handshake, protocols, record};
use alloc::rc;
use alloc::vec;
use core::mem;

mod error;
mod identity;
mod owned;
mod restore;
mod resumption;
pub(in crate::client) mod resumptions;
mod ticket;
mod truststore;

pub use error::Error;
pub use identity::Identity;
pub use identity::template::IdentityTemplate;
pub use owned::trust::anchor::OwnedTrustAnchor;
pub use restore::Restore;
pub use restore::alpn::NegotiatedAlpn;
pub use resumption::Resumption;
pub use ticket::Ticket;
pub use truststore::TrustStore;

pub const MAX_TRUST_ANCHORS: usize = 256;

/// Explicit upper bound for a peer's encoded TLS Certificate message.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateLimit(u32);

struct CertificateBound<const BYTES: usize>;

impl<const BYTES: usize> CertificateBound<BYTES> {
    const VALID: () = {
        assert!(BYTES >= record::MAX_PLAINTEXT_BODY);
        assert!(BYTES <= handshake::MAX_SIZE);
    };
}

impl CertificateLimit {
    pub const ONE_RECORD: Self = Self(record::MAX_PLAINTEXT_BODY as u32);
    pub const MAXIMUM: Self = Self(handshake::MAX_SIZE as u32);

    /// Creates a compile-time checked certificate-message bound.
    pub const fn new<const BYTES: usize>() -> Self {
        let () = CertificateBound::<BYTES>::VALID;
        Self(BYTES as u32)
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone)]
pub enum Verifier {
    RawPublicKey {
        expected_pubkey: [u8; sig::PUBKEY_LEN],
    },
    X509 {
        anchors: vec::Vec<OwnedTrustAnchor>,
        hostname: vec::Vec<u8>,
        certificate_limit: CertificateLimit,
    },
    /// X.509 verification backed by a reusable, issuer-indexed trust store.
    X509Store {
        roots: TrustStore,
        hostname: vec::Vec<u8>,
        certificate_limit: CertificateLimit,
    },
}

impl Verifier {
    pub(crate) fn dns_hostname(&self) -> Option<&[u8]> {
        use crate::identity::Hostname;
        match self {
            Self::X509 { hostname, .. } | Self::X509Store { hostname, .. }
                if !Hostname::new(hostname).is_ip_literal() =>
            {
                Some(hostname)
            }
            Self::RawPublicKey { .. } | Self::X509 { .. } | Self::X509Store { .. } => None,
        }
    }

    fn prepare(self) -> Result<Self, Error> {
        match self {
            Self::X509 {
                anchors,
                hostname,
                certificate_limit,
            } => Ok(Self::X509Store {
                roots: TrustStore::new(anchors)?,
                hostname,
                certificate_limit,
            }),
            verifier => Ok(verifier),
        }
    }

    const fn certificate_limit(&self) -> CertificateLimit {
        match self {
            Self::RawPublicKey { .. } => CertificateLimit::ONE_RECORD,
            Self::X509 {
                certificate_limit, ..
            }
            | Self::X509Store {
                certificate_limit, ..
            } => *certificate_limit,
        }
    }

    pub(in crate::client) const fn peer_identity_capacity(&self) -> usize {
        match self {
            Self::X509 { .. } | Self::X509Store { .. } => {
                crate::identity::leafkey::MAX_PEER_KEY_LEN
            }
            Self::RawPublicKey { .. } => 0,
        }
    }
}

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

/// Exact endpoint policy shared by an owned client or one client pool.
pub(in crate::client) struct Authority {
    template: Template,
    identity: Option<IdentityTemplate>,
}

pub(in crate::client) struct Policy<'a> {
    authority: &'a Authority,
    transport_params: Option<&'a [u8]>,
}

/// A validated template plus connection-local resumption state.
/// Construction proves the pair fits the initial TLS record.
pub struct Prepared {
    pub(super) template: Template,
    pub(super) resumption: Option<resumptions::Active>,
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
    pub fn workspace_layout(&self, identity: Option<&IdentityTemplate>) -> workspace::Layout {
        workspace::Layout::prepared(
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

    #[cfg(test)]
    pub(in crate::client) fn strong_count(&self) -> usize {
        rc::Rc::strong_count(&self.inner)
    }
}

impl Authority {
    pub(in crate::client) fn new(template: Template, identity: Option<IdentityTemplate>) -> Self {
        Self { template, identity }
    }

    pub(in crate::client) fn policy<'a>(
        &'a self,
        transport_params: Option<&'a [u8]>,
    ) -> Policy<'a> {
        Policy {
            authority: self,
            transport_params,
        }
    }

    pub(in crate::client) fn template(&self) -> &Template {
        &self.template
    }

    pub(in crate::client) fn identity(&self) -> Option<&IdentityTemplate> {
        self.identity.as_ref()
    }

    pub(in crate::client) fn workspace_layout(&self) -> workspace::Layout {
        self.template.workspace_layout(self.identity.as_ref())
    }

    pub(in crate::client) fn restore(
        &self,
        restore: Restore<'_>,
        transport_params_capacity: usize,
    ) -> Result<resumptions::Active, Error> {
        let active = restore.bind(&self.template);
        validate_initial_hello_capacity(
            self.template.transport_mode(),
            self.template.verifier(),
            transport_params_capacity,
            self.template.alpn_protocols(),
            Some(&active),
        )?;
        Ok(active)
    }

    #[cfg(test)]
    pub(in crate::client) fn strong_counts(&self) -> (usize, Option<usize>) {
        (
            self.template.strong_count(),
            self.identity.as_ref().map(IdentityTemplate::strong_count),
        )
    }
}

impl Policy<'_> {
    pub(in crate::client) fn template(&self) -> &Template {
        self.authority.template()
    }

    pub(in crate::client) fn identity(&self) -> Option<&IdentityTemplate> {
        self.authority.identity()
    }

    pub(in crate::client) fn transport_params(&self) -> &[u8] {
        self.transport_params
            .unwrap_or_else(|| self.template().transport_params())
    }
}

impl Prepared {
    /// Returns the exact workspace plan for this prepared connection.
    pub fn workspace_layout(&self, identity: Option<&IdentityTemplate>) -> workspace::Layout {
        self.template.workspace_layout(identity)
    }

    /// Builds an owned client for a transport that frames handshake messages
    /// and lends their final outbound owner.
    pub fn into_framed_client<C: connection::Clock>(
        self,
        identity: Option<IdentityTemplate>,
        clock: C,
    ) -> client::FramedClient<C> {
        let peer_identity = self.template.verifier().peer_identity_capacity();
        let workspace = workspace::Layout::framed(peer_identity).allocate();
        let Self {
            template,
            resumption,
            enable_early_data,
        } = self;
        client::FramedClient {
            core: client::FramedCore::new(clock, workspace, resumption, enable_early_data),
            authority: Authority::new(template, identity),
        }
    }

    /// Creates a fixed client pool that owns this endpoint policy once.
    pub fn into_pool<C: connection::Clock>(
        self,
        identity: Option<IdentityTemplate>,
        capacity: o3::collections::slab::Capacity,
    ) -> workspace::Pool<C> {
        workspace::Pool::new(self, identity, capacity)
    }

    /// Creates a pool for embedders that deliver exactly one framed handshake
    /// message at a time and prepare connection-local transport parameters in
    /// retained storage.
    pub fn try_into_framed_pool<C: connection::Clock>(
        self,
        identity: Option<IdentityTemplate>,
        capacity: o3::collections::slab::Capacity,
        transport_params_capacity: usize,
    ) -> Result<workspace::FramedPool<C>, Error> {
        validate_initial_hello_capacity(
            self.template.transport_mode(),
            self.template.verifier(),
            transport_params_capacity,
            self.template.alpn_protocols(),
            self.resumption.as_ref(),
        )?;
        Ok(workspace::FramedPool::new(
            self,
            identity,
            capacity,
            transport_params_capacity,
        ))
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
        storage: workspace::Workspace,
    ) -> Result<client::Client<C>, workspace::Rejection> {
        let layout = self.workspace_layout(identity.as_ref());
        let storage = layout.admit(storage)?;
        Ok(self.build_client(identity, clock, storage))
    }

    pub(in crate::client) fn build_client<C: connection::Clock>(
        self,
        identity: Option<IdentityTemplate>,
        clock: C,
        storage: workspace::Workspace,
    ) -> client::Client<C> {
        let Self {
            template,
            resumption,
            enable_early_data,
        } = self;
        client::Client {
            core: client::Core::new(clock, storage, resumption, enable_early_data),
            authority: Authority::new(template, identity),
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
    resumption: Option<&resumptions::Active>,
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

fn validate_initial_hello_capacity(
    transport_mode: transport::Mode,
    verifier: &Verifier,
    transport_params_len: usize,
    alpn_protocols: &[vec::Vec<u8>],
    resumption: Option<&resumptions::Active>,
) -> Result<(), Error> {
    use crate::client::offer::Offer;
    use crate::wire::record::MAX_PLAINTEXT_BODY;
    if transport_params_len > u16::MAX as usize {
        return Err(Error::TransportParametersTooLong {
            len: transport_params_len,
            maximum: u16::MAX as usize,
        });
    }
    if transport_mode.is_tls() && transport_params_len != 0 {
        return Err(Error::TransportParametersInTls {
            len: transport_params_len,
        });
    }
    let len = Offer::maximum_initial_len_for_transport_params(
        transport_mode,
        verifier,
        transport_params_len,
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
