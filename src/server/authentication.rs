use super::*;

pub(super) trait ClientAuthentication {
    fn handle_end_of_early_data(
        &mut self,
        raw: &[u8],
        client_handshake_traffic: Digest,
    ) -> Result<(), Error>;
    fn expect_client_finished(&mut self, client_handshake_traffic: Digest) -> Result<(), Error>;
    fn handle_client_certificate(
        &mut self,
        cert: CertificateRef<'_>,
        raw: &[u8],
        client_handshake_traffic: Digest,
        client_auth: Option<ClientAuth>,
    ) -> Result<(), Error>;
    fn handle_client_cert_verify<G: EarlyDataGuard, V: ClientCertVerifier>(
        &mut self,
        cv: CertificateVerifyRef<'_>,
        raw: &[u8],
        client_handshake_traffic: Digest,
        shard: &Shard<G, V>,
    ) -> Result<(), Error>;
}
impl<C: Clock> ClientAuthentication for Server<C> {
    fn handle_end_of_early_data(
        &mut self,
        raw: &[u8],
        client_handshake_traffic: Digest,
    ) -> Result<(), Error> {
        self.early_data.close();
        self.transcript.update(raw);
        self.expect_client_finished(client_handshake_traffic)
    }

    fn expect_client_finished(&mut self, client_handshake_traffic: Digest) -> Result<(), Error> {
        let h = self.transcript.hash(self.hash_alg());
        let verify_data = Finished::verify_data(
            self.hash_alg(),
            client_handshake_traffic.as_slice(),
            h.as_slice(),
        )?;
        self.state = State::ExpectClientFinished { verify_data };
        Ok(())
    }

    /// Mutual TLS: the client's Certificate (RFC 8446 §4.4.2). Capture the leaf
    /// key for the CertificateVerify that follows; an empty list is an anonymous
    /// client (allowed only under `Requested`).
    fn handle_client_certificate(
        &mut self,
        cert: CertificateRef<'_>,
        raw: &[u8],
        client_handshake_traffic: Digest,
        client_auth: Option<ClientAuth>,
    ) -> Result<(), Error> {
        if !cert.certificate_request_context.is_empty() {
            return Err(Error::IllegalParameter);
        }
        if cert.certificate_list.is_empty() {
            if client_auth == Some(ClientAuth::Required) {
                return Err(Error::ClientCertRequired);
            }
            self.transcript.update(raw);
            return self.expect_client_finished(client_handshake_traffic);
        }
        let leaf_entry = cert.certificate_list.first().ok_or(Error::BadCertificate)?;
        let leaf_key = if self.negotiated_client_cert_type == CERT_TYPE_RAW_PUBLIC_KEY {
            if cert.certificate_list.len() != 1 {
                return Err(Error::BadCertificate);
            }
            LeafKey::from_spki(leaf_entry.cert_data)?
        } else {
            LeafKey::parse_x509(leaf_entry.cert_data)?.0
        };
        self.identity_workspace.clear();
        self.identity_workspace
            .try_extend_from_slice(raw)
            .map_err(|_| Error::WorkspaceExhausted(WorkspaceRegion::PeerIdentity))?;
        self.client_leaf = Some(leaf_key);
        self.transcript.update(raw);
        self.state = State::ExpectClientCertVerify {
            client_handshake_traffic,
        };
        Ok(())
    }

    /// Mutual TLS: the client's CertificateVerify (RFC 8446 §4.4.3). Verify
    /// possession of the leaf key, then ask the embedder to authorize the
    /// pinned identity. Only then is the expected client Finished computed.
    fn handle_client_cert_verify<G: EarlyDataGuard, V: ClientCertVerifier>(
        &mut self,
        cv: CertificateVerifyRef<'_>,
        raw: &[u8],
        client_handshake_traffic: Digest,
        shard: &Shard<G, V>,
    ) -> Result<(), Error> {
        if !SignatureAlgorithms::x509_supported(cv.algorithm) {
            return Err(Error::SigSchemeNotOffered);
        }
        let leaf = self
            .client_leaf
            .as_ref()
            .ok_or(Error::BadCertificateVerify)?;
        let h_pre_cv = self.transcript.hash(self.hash_alg());
        let msg = CertificateVerify::message(h_pre_cv.as_slice(), false)?;
        leaf.verify(cv.algorithm, &msg, cv.signature)?;

        if shard.client_auth.is_none() {
            return Err(Error::UnexpectedMessage);
        }
        let certificate = match HandshakeRef::decode(self.identity_workspace.as_slice())? {
            HandshakeRef::Certificate(certificate) => certificate,
            _ => return Err(Error::UnexpectedMessage),
        };
        let leaf_entry = certificate
            .certificate_list
            .first()
            .ok_or(Error::BadCertificate)?;
        let (spki_der, entries) = if self.negotiated_client_cert_type == CERT_TYPE_RAW_PUBLIC_KEY {
            (leaf_entry.cert_data, None)
        } else {
            (
                LeafKey::parse_x509(leaf_entry.cert_data)?.1,
                Some(certificate.certificate_list),
            )
        };
        let identity = ClientIdentity {
            cert_type: self.negotiated_client_cert_type,
            spki_der,
            chain_der: ClientCertificateChain { entries },
        };
        if !shard.verifier.verify(&identity) {
            return Err(Error::AccessDenied);
        }

        self.transcript.update(raw);
        self.expect_client_finished(client_handshake_traffic)
    }
}
