use crate::server::config;
use crate::wire::handshake;
use crate::wire::handshake::workspace;
use crate::wire::record;
use core::{marker, mem};

mod private {
    pub trait Sealed {}
}

/// Closed proof that a verifier has a reviewed server workspace profile.
///
/// The verifier type fixes whether peer-identity storage is reachable; the
/// shard's validated configuration supplies the exact runtime flight bound.
pub trait WorkspaceProfile: config::ClientCertVerifier + private::Sealed + Sized {}

impl private::Sealed for config::NoClientAuth {}
impl WorkspaceProfile for config::NoClientAuth {}

impl<V: config::ClientCertVerifier> private::Sealed for config::ClientAuthVerifier<V> {}
impl<V: config::ClientCertVerifier> WorkspaceProfile for config::ClientAuthVerifier<V> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    fragmented_message: usize,
    outbound_flight: usize,
    peer_identity: usize,
}

/// Exact, validated reservation plan for one server connection.
///
/// Its verifier parameter prevents a standard workspace from entering a
/// mutual-authentication pool. Runtime certificate, ALPN, and transport sizes
/// remain values because they are not compile-time properties.
pub struct WorkspaceLayout<V: config::ClientCertVerifier = config::NoClientAuth> {
    inner: Layout,
    _profile: marker::PhantomData<fn(V) -> V>,
}

impl<V: config::ClientCertVerifier> Copy for WorkspaceLayout<V> {}

impl<V: config::ClientCertVerifier> Clone for WorkspaceLayout<V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: config::ClientCertVerifier> WorkspaceLayout<V> {
    pub(super) fn new(outbound_flight: usize, peer_identity: usize) -> Self {
        let one_record = record::MAX_PLAINTEXT_BODY;
        Self {
            inner: Layout {
                fragmented_message: one_record.max(peer_identity),
                outbound_flight: one_record.max(outbound_flight),
                peer_identity,
            },
            _profile: marker::PhantomData,
        }
    }

    /// Allocates every byte described by this plan before admission.
    pub fn allocate(self) -> Workspace<V> {
        Workspace::new(workspace::Scratch::new(
            self.inner.fragmented_message,
            self.inner.outbound_flight,
            self.inner.peer_identity,
        ))
    }

    pub fn capacities(self) -> (usize, usize, usize) {
        (
            self.inner.fragmented_message,
            self.inner.outbound_flight,
            self.inner.peer_identity,
        )
    }
}

impl<V: config::ClientCertVerifier> PartialEq for WorkspaceLayout<V> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<V: config::ClientCertVerifier> Eq for WorkspaceLayout<V> {}

/// Opaque, fully reserved storage for one validated server profile.
///
/// Workspaces are created only from [`WorkspaceLayout::allocate`], so their
/// logical limits and physical `Vec` reservations are identical. Recycling
/// clears protocol bytes without weakening the verifier profile.
///
/// ```compile_fail
/// use shin::server::{Workspace, config};
///
/// struct Verifier;
/// impl config::ClientCertVerifier for Verifier {
///     fn verify(&self, _: &config::ClientIdentity<'_>) -> bool { true }
/// }
///
/// fn erase(
///     workspace: Workspace<config::ClientAuthVerifier<Verifier>>,
/// ) -> Workspace {
///     workspace
/// }
/// ```
///
/// Raw scratch storage cannot enter the typed server pool boundary:
///
/// ```compile_fail
/// use shin::server::Workspace;
/// use shin::wire::handshake::workspace::Scratch;
///
/// fn bypass(scratch: Scratch) -> Workspace {
///     scratch
/// }
/// ```
pub struct Workspace<V: config::ClientCertVerifier = config::NoClientAuth> {
    scratch: workspace::Scratch,
    _profile: marker::PhantomData<fn(V) -> V>,
}

impl<V: config::ClientCertVerifier> Workspace<V> {
    fn new(scratch: workspace::Scratch) -> Self {
        Self {
            scratch,
            _profile: marker::PhantomData,
        }
    }

    pub(super) fn into_scratch(self) -> workspace::Scratch {
        self.scratch
    }

    pub(super) fn from_recycled(scratch: workspace::Scratch) -> Self {
        Self::new(scratch)
    }
}

const _: () = assert!(mem::size_of::<Workspace>() == mem::size_of::<workspace::Scratch>());
const _: () = assert!(record::MAX_PLAINTEXT_BODY <= handshake::MAX_SIZE);
