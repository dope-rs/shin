use crate::transport;
use alloc::rc;
use alloc::vec;
use core::mem;

mod error;
mod identity;
mod owned;
mod resumption;
mod verifier;

pub use error::Error;
pub use identity::Identity;
pub use identity::template::IdentityTemplate;
pub use owned::trust::anchor::OwnedTrustAnchor;
pub use resumption::Resumption;
pub use verifier::Verifier;

pub const MAX_TRUST_ANCHORS: usize = 256;

pub struct Config {
    pub verifier: Verifier,
    pub transport_params: vec::Vec<u8>,
    pub alpn_protocols: vec::Vec<vec::Vec<u8>>,
    pub resumption: Option<Resumption>,
    pub enable_early_data: bool,
}

/// Immutable, cheaply cloned client configuration shared by connections that
/// use the same endpoint policy. Resumption remains connection-local and is
/// deliberately split out when a [`Config`] becomes a template.
#[derive(Clone)]
pub struct Template {
    inner: rc::Rc<Shared>,
}

/// A validated template plus connection-local resumption state.
/// Construction proves the pair fits the initial TLS record.
pub struct Prepared {
    pub(super) template: Template,
    pub(super) resumption: Option<Resumption>,
}

struct Shared {
    verifier: Verifier,
    transport_mode: transport::Mode,
    transport_params: vec::Vec<u8>,
    alpn_protocols: vec::Vec<vec::Vec<u8>>,
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
        if let Verifier::X509 { anchors, hostname } = &self.verifier {
            use crate::identity::Hostname;
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
            if hostname.is_empty() {
                return Err(Error::MissingServerName);
            }
            if !Hostname::new(hostname).is_valid_reference() {
                return Err(Error::InvalidServerName);
            }
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
        validate_resumption(self.resumption.as_ref())?;
        validate_initial_hello(
            transport_mode,
            &self.verifier,
            &self.transport_params,
            &self.alpn_protocols,
            self.resumption.as_ref(),
        )?;
        Ok(())
    }

    /// Validates reusable endpoint policy once, then splits it from the
    /// single-use resumption ticket in TLS-over-stream mode.
    pub fn try_into_template(self) -> Result<(Template, Option<Resumption>), Error> {
        self.try_into_template_with_transport(transport::Mode::Tls)
    }

    /// Validates reusable endpoint policy for an explicit transport.
    pub fn try_into_template_with_transport(
        self,
        transport_mode: transport::Mode,
    ) -> Result<(Template, Option<Resumption>), Error> {
        self.validate_with_transport(transport_mode)?;
        Ok(self.split_template(transport_mode))
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
        self.validate_with_transport(transport_mode)?;
        let (template, resumption) = self.split_template(transport_mode);
        Ok(Prepared {
            template,
            resumption,
        })
    }

    fn split_template(mut self, transport_mode: transport::Mode) -> (Template, Option<Resumption>) {
        let resumption = self.resumption.take();
        let inner = Shared {
            verifier: self.verifier,
            transport_mode,
            transport_params: self.transport_params,
            alpn_protocols: self.alpn_protocols,
            enable_early_data: self.enable_early_data,
        };
        (
            Template {
                inner: rc::Rc::new(inner),
            },
            resumption,
        )
    }
}

impl Template {
    /// Attaches connection-local state while preserving the encoded-size proof.
    pub fn with_resumption(self, resumption: Option<Resumption>) -> Result<Prepared, Error> {
        validate_resumption(resumption.as_ref())?;
        validate_initial_hello(
            self.inner.transport_mode,
            &self.inner.verifier,
            &self.inner.transport_params,
            &self.inner.alpn_protocols,
            resumption.as_ref(),
        )?;
        Ok(Prepared {
            template: self,
            resumption,
        })
    }

    /// Removing resumption can only reduce a previously validated ClientHello.
    pub fn without_resumption(self) -> Prepared {
        Prepared {
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
        &self.inner.alpn_protocols
    }

    pub(crate) fn enable_early_data(&self) -> bool {
        self.inner.enable_early_data
    }
}

impl Prepared {
    /// Returns the validated reusable policy without exposing resumption state.
    pub fn template(&self) -> Template {
        self.template.clone()
    }
}

fn validate_resumption(resumption: Option<&Resumption>) -> Result<(), Error> {
    let Some(resumption) = resumption else {
        return Ok(());
    };
    if resumption.ticket.is_empty() {
        return Err(Error::EmptyResumptionTicket);
    }
    if resumption.ticket.len() > u16::MAX as usize {
        return Err(Error::ResumptionTicketTooLong {
            len: resumption.ticket.len(),
            maximum: u16::MAX as usize,
        });
    }
    Ok(())
}

fn validate_initial_hello(
    transport_mode: transport::Mode,
    verifier: &Verifier,
    transport_params: &[u8],
    alpn_protocols: &[vec::Vec<u8>],
    resumption: Option<&Resumption>,
) -> Result<(), Error> {
    use crate::client::offer::Hello;
    use crate::wire::record::MAX_PLAINTEXT_BODY;
    let len = Hello::maximum_initial_len(
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
