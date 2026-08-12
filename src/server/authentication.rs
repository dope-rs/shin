use crate::connection;
use crate::crypto::material;
use crate::identity;
use crate::identity::leafkey;
use crate::server;
use crate::server::config;
use crate::server::session;
use crate::wire::handshake::views;

struct PresentedClientIdentity<'a> {
    leaf: leafkey::LeafKey<'a>,
    public: config::ClientIdentity<'a>,
}

impl<'a> PresentedClientIdentity<'a> {
    fn parse(
        certificate: views::CertificateRef<'a>,
        cert_type: identity::CertificateType,
    ) -> Result<Self, connection::Error> {
        use crate::server::config::ClientCertificateChain;
        let leaf_entry = certificate
            .certificate_list
            .first()
            .ok_or(connection::Error::BadCertificate)?;
        let (leaf, spki_der, entries) = match cert_type {
            identity::CertificateType::RawPublicKey => {
                if certificate.certificate_list.len() != 1 {
                    return Err(connection::Error::BadCertificate);
                }
                (
                    leafkey::LeafKey::from_spki(leaf_entry.cert_data)?,
                    leaf_entry.cert_data,
                    None,
                )
            }
            identity::CertificateType::X509 => {
                let (leaf, spki_der) = leafkey::LeafKey::parse_x509(leaf_entry.cert_data)?;
                (leaf, spki_der, Some(certificate.certificate_list))
            }
        };
        Ok(Self {
            leaf,
            public: config::ClientIdentity {
                cert_type,
                spki_der,
                chain_der: ClientCertificateChain { entries },
            },
        })
    }
}

pub(super) trait Authentication {
    fn handle_end_of_early_data(
        &mut self,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
    ) -> Result<(), connection::Error>;
    fn expect_client_finished(
        &mut self,
        client_handshake_traffic: material::TrafficSecret,
    ) -> Result<(), connection::Error>;
    fn handle_client_certificate(
        &mut self,
        cert: views::CertificateRef<'_>,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
        client_auth: Option<config::ClientAuth>,
    ) -> Result<(), connection::Error>;
    fn handle_client_cert_verify<
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        const DOMAIN: u8,
    >(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
        shard: &server::Shard<G, V, DOMAIN>,
    ) -> Result<(), connection::Error>;
}
impl<C: connection::Clock, const SERVER_DOMAIN: u8> Authentication
    for server::Server<C, SERVER_DOMAIN>
{
    fn handle_end_of_early_data(
        &mut self,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
    ) -> Result<(), connection::Error> {
        self.session.peer.early_data.close();
        self.session.handshake.transcript.update(raw);
        self.expect_client_finished(client_handshake_traffic)
    }

    fn expect_client_finished(
        &mut self,
        client_handshake_traffic: material::TrafficSecret,
    ) -> Result<(), connection::Error> {
        use crate::wire::handshake::messages::Finished;
        let algorithm = self.session.application.hash_alg()?;
        let h = self.session.handshake.transcript.hash(algorithm)?;
        let verify_data =
            Finished::verify_data(algorithm, client_handshake_traffic.as_slice(), h.as_slice())?;
        self.session.handshake.state = session::State::ExpectClientFinished { verify_data };
        Ok(())
    }

    /// Mutual TLS: validate and retain the client's Certificate bytes for the
    /// CertificateVerify that follows. An empty list is an anonymous client
    /// (allowed only under `Requested`).
    fn handle_client_certificate(
        &mut self,
        cert: views::CertificateRef<'_>,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
        client_auth: Option<config::ClientAuth>,
    ) -> Result<(), connection::Error> {
        use crate::connection::WorkspaceRegion;
        if !cert.certificate_request_context.is_empty() {
            return Err(connection::Error::IllegalParameter);
        }
        if cert.certificate_list.is_empty() {
            if client_auth == Some(config::ClientAuth::Required) {
                return Err(connection::Error::ClientCertRequired);
            }
            self.session.handshake.transcript.update(raw);
            return self.expect_client_finished(client_handshake_traffic);
        }
        PresentedClientIdentity::parse(cert, self.session.peer.client_cert_type)?;
        self.session.buffers.identity_workspace.clear();
        self.session
            .buffers
            .identity_workspace
            .try_extend(raw)
            .map_err(|_| connection::Error::WorkspaceExhausted(WorkspaceRegion::PeerIdentity))?;
        self.session.handshake.transcript.update(raw);
        self.session.handshake.state = session::State::ExpectClientCertVerify {
            client_handshake_traffic,
        };
        Ok(())
    }

    /// Mutual TLS: the client's CertificateVerify (RFC 8446 §4.4.3). Verify
    /// possession of the leaf key, then ask the embedder to authorize the
    /// pinned identity. Only then is the expected client Finished computed.
    fn handle_client_cert_verify<
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        const DOMAIN: u8,
    >(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
        shard: &server::Shard<G, V, DOMAIN>,
    ) -> Result<(), connection::Error> {
        use crate::wire::handshake::messages::CertificateVerify;
        use crate::wire::protocols::SignatureAlgorithms;
        if !SignatureAlgorithms::x509_supported(cv.algorithm) {
            return Err(connection::Error::SigSchemeNotOffered);
        }
        let algorithm = self.session.application.hash_alg()?;
        let h_pre_cv = self.session.handshake.transcript.hash(algorithm)?;
        let msg = CertificateVerify::message(h_pre_cv.as_slice(), false)?;
        {
            let certificate = match views::MessageRef::decode(
                self.session.buffers.identity_workspace.as_slice(),
            )? {
                views::MessageRef::Certificate(certificate) => certificate,
                _ => return Err(connection::Error::UnexpectedMessage),
            };
            let presented =
                PresentedClientIdentity::parse(certificate, self.session.peer.client_cert_type)?;
            presented.leaf.verify(cv.algorithm, &msg, cv.signature)?;

            if shard.policy.client_auth.is_none() {
                return Err(connection::Error::UnexpectedMessage);
            }
            if !shard.policy.verifier.verify(&presented.public) {
                return Err(connection::Error::AccessDenied);
            }
        }

        self.session.buffers.identity_workspace.clear();
        self.session.handshake.transcript.update(raw);
        self.expect_client_finished(client_handshake_traffic)
    }
}
