use crate::connection;
use crate::crypto::material;
use crate::identity::leafkey;
use crate::server;
use crate::server::config;
use crate::server::session;
use crate::wire::handshake::views;
use crate::wire::protocols;

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
    fn handle_client_cert_verify<G: config::EarlyDataGuard, V: config::ClientCertVerifier>(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
        shard: &server::Shard<G, V>,
    ) -> Result<(), connection::Error>;
}
impl<C: connection::Clock> Authentication for server::Server<C> {
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

    /// Mutual TLS: the client's Certificate (RFC 8446 §4.4.2). Capture the leaf
    /// key for the CertificateVerify that follows; an empty list is an anonymous
    /// client (allowed only under `Requested`).
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
        let leaf_entry = cert
            .certificate_list
            .first()
            .ok_or(connection::Error::BadCertificate)?;
        let leaf_key = if self.session.peer.client_cert_type == protocols::CERT_TYPE_RAW_PUBLIC_KEY
        {
            if cert.certificate_list.len() != 1 {
                return Err(connection::Error::BadCertificate);
            }
            leafkey::LeafKey::from_spki(leaf_entry.cert_data)?
        } else {
            leafkey::LeafKey::parse_x509(leaf_entry.cert_data)?.0
        };
        self.session.buffers.identity_workspace.clear();
        self.session
            .buffers
            .identity_workspace
            .try_extend(raw)
            .map_err(|_| connection::Error::WorkspaceExhausted(WorkspaceRegion::PeerIdentity))?;
        self.session.peer.client_leaf = Some(leaf_key);
        self.session.handshake.transcript.update(raw);
        self.session.handshake.state = session::State::ExpectClientCertVerify {
            client_handshake_traffic,
        };
        Ok(())
    }

    /// Mutual TLS: the client's CertificateVerify (RFC 8446 §4.4.3). Verify
    /// possession of the leaf key, then ask the embedder to authorize the
    /// pinned identity. Only then is the expected client Finished computed.
    fn handle_client_cert_verify<G: config::EarlyDataGuard, V: config::ClientCertVerifier>(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        client_handshake_traffic: material::TrafficSecret,
        shard: &server::Shard<G, V>,
    ) -> Result<(), connection::Error> {
        use crate::server::config::ClientCertificateChain;
        use crate::server::config::ClientIdentity;
        use crate::wire::handshake::messages::CertificateVerify;
        use crate::wire::handshake::views::MessageRef;
        use crate::wire::protocols::SignatureAlgorithms;
        if !SignatureAlgorithms::x509_supported(cv.algorithm) {
            return Err(connection::Error::SigSchemeNotOffered);
        }
        let leaf = self
            .session
            .peer
            .client_leaf
            .as_ref()
            .ok_or(connection::Error::BadCertificateVerify)?;
        let algorithm = self.session.application.hash_alg()?;
        let h_pre_cv = self.session.handshake.transcript.hash(algorithm)?;
        let msg = CertificateVerify::message(h_pre_cv.as_slice(), false)?;
        leaf.verify(cv.algorithm, &msg, cv.signature)?;

        if shard.policy.client_auth.is_none() {
            return Err(connection::Error::UnexpectedMessage);
        }
        let certificate =
            match MessageRef::decode(self.session.buffers.identity_workspace.as_slice())? {
                MessageRef::Certificate(certificate) => certificate,
                _ => return Err(connection::Error::UnexpectedMessage),
            };
        let leaf_entry = certificate
            .certificate_list
            .first()
            .ok_or(connection::Error::BadCertificate)?;
        let (spki_der, entries) =
            if self.session.peer.client_cert_type == protocols::CERT_TYPE_RAW_PUBLIC_KEY {
                (leaf_entry.cert_data, None)
            } else {
                (
                    leafkey::LeafKey::parse_x509(leaf_entry.cert_data)?.1,
                    Some(certificate.certificate_list),
                )
            };
        let identity = ClientIdentity {
            cert_type: self.session.peer.client_cert_type,
            spki_der,
            chain_der: ClientCertificateChain { entries },
        };
        if !shard.policy.verifier.verify(&identity) {
            return Err(connection::Error::AccessDenied);
        }

        self.session.handshake.transcript.update(raw);
        self.expect_client_finished(client_handshake_traffic)
    }
}
