use crate::connection;
use crate::crypto::hash;
use crate::crypto::kx;
use crate::server;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use crate::wire::handshake;
use crate::wire::handshake::views;
use crate::wire::protocols;

/// Heap-free snapshot of the parts of ClientHello which RFC 8446 forbids a
/// client from changing across HelloRetryRequest.
#[derive(Clone, Copy)]
pub(super) struct ClientHelloInvariant {
    fingerprint: hash::Digest,
    requested_group: kx::KexGroup,
}

impl ClientHelloInvariant {
    pub(super) fn capture(
        hello: views::ClientHelloRef<'_>,
        requested_group: kx::KexGroup,
    ) -> Result<Self, connection::Error> {
        Ok(Self {
            fingerprint: fingerprint(hello)?,
            requested_group,
        })
    }

    pub(super) fn validate(
        self,
        hello: views::ClientHelloRef<'_>,
    ) -> Result<(), connection::Error> {
        if hello.extensions.find(extension::Type::EARLY_DATA).is_some() {
            return Err(connection::Error::IllegalParameter);
        }
        validate_retry_key_share(hello, self.requested_group)?;
        if fingerprint(hello)? != self.fingerprint {
            return Err(connection::Error::IllegalParameter);
        }
        Ok(())
    }
}

const PADDING: extension::Type = extension::Type(21);

fn fingerprint(hello: views::ClientHelloRef<'_>) -> Result<hash::Digest, connection::Error> {
    let mut transcript = hash::Transcript::new();
    transcript.select(hash::Algorithm::Sha256)?;
    transcript.update(b"shin hrr client hello invariant v1");
    transcript.update(&hello.legacy_version.to_be_bytes());
    transcript.update(&hello.random);
    update_bytes(&mut transcript, hello.legacy_session_id);

    let suite_count = hello.cipher_suites.iter().count() as u32;
    transcript.update(&suite_count.to_be_bytes());
    for suite in hello.cipher_suites.iter() {
        transcript.update(&suite.to_be_bytes());
    }
    update_bytes(&mut transcript, hello.legacy_compression_methods);

    let invariant_extension_count = hello
        .extensions
        .iter()
        .filter(|extension| !is_fully_mutable(extension.ty))
        .count() as u32;
    transcript.update(&invariant_extension_count.to_be_bytes());
    for extension in hello.extensions.iter() {
        if extension.ty == PADDING {
            if extension.data.iter().any(|byte| *byte != 0) {
                return Err(connection::Error::IllegalParameter);
            }
            continue;
        }
        if is_fully_mutable(extension.ty) {
            continue;
        }
        transcript.update(&extension.ty.0.to_be_bytes());
        if extension.ty == extension::Type::PRE_SHARED_KEY {
            update_psk_invariant(&mut transcript, extension.data)?;
        } else {
            update_bytes(&mut transcript, extension.data);
        }
    }
    Ok(transcript.hash(hash::Algorithm::Sha256)?)
}

fn is_fully_mutable(ty: extension::Type) -> bool {
    matches!(
        ty,
        extension::Type::COOKIE | extension::Type::KEY_SHARE | extension::Type::EARLY_DATA
    ) || ty == PADDING
}

fn update_bytes(transcript: &mut hash::Transcript, bytes: &[u8]) {
    transcript.update(&(bytes.len() as u32).to_be_bytes());
    transcript.update(bytes);
}

/// Preserve PSK identities, ticket ages, binder count, and binder lengths,
/// while allowing only the binder bytes themselves to be recomputed for CH2.
fn update_psk_invariant(
    transcript: &mut hash::Transcript,
    encoded: &[u8],
) -> Result<(), connection::Error> {
    use crate::wire::codec::Reader;
    let mut reader = Reader::new(encoded);
    let identities = reader.vec_u16()?;
    let binders = reader.vec_u16()?;
    reader.finish()?;

    let mut identity_reader = Reader::new(identities);
    let mut identity_count = 0u32;
    while !identity_reader.is_empty() {
        identity_reader.vec_u16()?;
        identity_reader.u32()?;
        identity_count = identity_count
            .checked_add(1)
            .ok_or(connection::Error::Decode)?;
    }

    let mut binder_reader = Reader::new(binders);
    let mut binder_count = 0u32;
    while !binder_reader.is_empty() {
        binder_reader.vec_u8()?;
        binder_count = binder_count
            .checked_add(1)
            .ok_or(connection::Error::Decode)?;
    }
    if identity_count != binder_count {
        return Err(connection::Error::Decode);
    }

    transcript.update(&identity_count.to_be_bytes());
    update_bytes(transcript, identities);
    transcript.update(&binder_count.to_be_bytes());
    let mut binder_reader = Reader::new(binders);
    while !binder_reader.is_empty() {
        let binder = binder_reader.vec_u8()?;
        transcript.update(&(binder.len() as u32).to_be_bytes());
    }
    Ok(())
}

fn validate_retry_key_share(
    hello: views::ClientHelloRef<'_>,
    requested_group: kx::KexGroup,
) -> Result<(), connection::Error> {
    use crate::wire::codec::Reader;
    let encoded = hello
        .extensions
        .find(extension::Type::KEY_SHARE)
        .ok_or(connection::Error::MissingExtension)?
        .data;
    let mut reader = Reader::new(encoded);
    let mut entries = reader.sub_u16()?;
    let group = entries.u16()?;
    entries.vec_u16()?;
    entries.finish()?;
    reader.finish()?;
    if group != requested_group.wire_id() {
        return Err(connection::Error::IllegalParameter);
    }
    Ok(())
}

pub(super) trait Retry {
    fn send_hello_retry_request<S: connection::EventSink + ?Sized>(
        &mut self,
        client_hello: &[u8],
        session_id_echo: &[u8],
        request_group: kx::KexGroup,
        invariant: ClientHelloInvariant,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}

impl<C: connection::Clock> Retry for server::Server<C> {
    /// RFC 8446 §4.1.4: ask for a retry (one only) when the ClientHello carried
    /// no usable key_share, rewriting the transcript to `message_hash(CH1)`.
    fn send_hello_retry_request<S: connection::EventSink + ?Sized>(
        &mut self,
        client_hello: &[u8],
        session_id_echo: &[u8],
        request_group: kx::KexGroup,
        invariant: ClientHelloInvariant,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::wire::handshake::HELLO_RETRY_REQUEST_RANDOM;
        let suite = self
            .session
            .application
            .traffic
            .suite()
            .ok_or(connection::Error::UnsupportedCipherSuite)?;
        self.session.buffers.flight.clear();
        self.session
            .buffers
            .flight
            .put_u8(handshake::Type::ServerHello as u8);
        let mut hello = self.session.buffers.flight.begin_u24()?;
        hello.put_u16(handshake::TLS_1_2);
        hello.put_slice(&HELLO_RETRY_REQUEST_RANDOM);
        let mut session = hello.begin_u8()?;
        session.put_slice(session_id_echo);
        session.finish()?;
        hello.put_u16(suite.wire_id());
        hello.put_u8(0);
        let mut extensions = hello.begin_u16()?;
        let mut version =
            extension::Extension::begin(&mut extensions, extension::Type::SUPPORTED_VERSIONS)?;
        version.put_u16(protocols::TLS_1_3);
        version.finish()?;
        let mut group = extension::Extension::begin(&mut extensions, extension::Type::KEY_SHARE)?;
        group.put_u16(request_group.wire_id());
        group.finish()?;
        extensions.finish()?;
        hello.finish()?;

        let algorithm = self.session.application.hash_alg()?;
        self.session.handshake.transcript.update(client_hello);
        let client_hello_hash = self
            .session
            .handshake
            .transcript
            .hash(algorithm)
            .map_err(connection::Error::from)?;
        self.session.handshake.transcript =
            hash::Transcript::restart_with_message_hash(algorithm, &client_hello_hash)
                .map_err(connection::Error::from)?;
        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight);

        self.session.handshake.hrr_done = true;
        self.session.handshake.hrr_invariant = Some(invariant);
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::Send {
                epoch: connection::Epoch::Plaintext,
                data: &self.session.buffers.flight,
            },
        )?;
        Ok(())
    }
}
