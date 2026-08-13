use crate::connection;
use crate::server;
use crate::server::config;
use crate::server::session;
use crate::server::session::authentication;
use crate::server::session::hello;
use crate::server::session::resumption;
use crate::wire::handshake::reassemblers;
use crate::wire::handshake::views;
use core::mem;

pub(in crate::server) struct Drive<'session, C> {
    session: &'session mut session::Session<C>,
}

const _: () = assert!(mem::size_of::<Drive<'static, ()>>() == mem::size_of::<usize>());

impl<'session, C: connection::Clock> Drive<'session, C> {
    pub(in crate::server) fn new(session: &'session mut session::Session<C>) -> Self {
        Self { session }
    }

    pub(in crate::server) fn read<G, V, S, const DOMAIN: u8>(
        mut self,
        reassembler: &mut reassemblers::HsReassembler,
        epoch: connection::Epoch,
        data: &[u8],
        authority: &server::Authority<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        reassembler.read(epoch, data, |raw| {
            let message = views::MessageRef::decode(raw)?;
            self.process(epoch, message, raw, authority, events)
        })
    }

    pub(in crate::server) fn read_framed<G, V, S, const DOMAIN: u8>(
        mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        authority: &server::Authority<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        let message = views::MessageRef::decode(raw)?;
        self.process(epoch, message, raw, authority, events)
    }

    fn process<G, V, S, const DOMAIN: u8>(
        &mut self,
        epoch: connection::Epoch,
        message: views::MessageRef<'_>,
        raw: &[u8],
        authority: &server::Authority<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        let state = mem::replace(&mut self.session.handshake.state, session::State::Failed);
        match (state, message) {
            (session::State::ExpectClientHello, views::MessageRef::ClientHello(client_hello))
                if epoch == connection::Epoch::Plaintext =>
            {
                self.session.handshake.state = session::State::ExpectClientHello;
                hello::Hello::new(&mut *self.session).handle_client_hello(
                    client_hello,
                    raw,
                    authority,
                    events,
                )
            }
            (
                session::State::ExpectEndOfEarlyData {
                    client_handshake_traffic,
                },
                views::MessageRef::EndOfEarlyData,
            ) if epoch == connection::Epoch::Handshake => {
                authentication::Authentication::new(&mut *self.session)
                    .handle_end_of_early_data(raw, client_handshake_traffic)?;
                Ok(())
            }
            (
                session::State::ExpectClientCertificate {
                    client_handshake_traffic,
                },
                views::MessageRef::Certificate(certificate),
            ) if epoch == connection::Epoch::Handshake => {
                authentication::Authentication::new(&mut *self.session).handle_client_certificate(
                    certificate,
                    raw,
                    client_handshake_traffic,
                    authority.client_auth,
                )?;
                Ok(())
            }
            (
                session::State::ExpectClientCertVerify {
                    client_handshake_traffic,
                },
                views::MessageRef::CertificateVerify(verify),
            ) if epoch == connection::Epoch::Handshake => {
                authentication::Authentication::new(&mut *self.session).handle_client_cert_verify(
                    verify,
                    raw,
                    client_handshake_traffic,
                    authority,
                )?;
                Ok(())
            }
            (
                session::State::ExpectClientFinished { verify_data },
                views::MessageRef::Finished(finished),
            ) if epoch == connection::Epoch::Handshake => resumption::Resumption::new(
                &mut *self.session,
            )
            .handle_client_finished(finished, raw, verify_data, authority, events),
            (session::State::Done, views::MessageRef::KeyUpdate(update))
                if epoch == connection::Epoch::Application =>
            {
                self.session.handshake.state = session::State::Done;
                self.session.handle_key_update(update, events)
            }
            _ => Err(connection::Error::UnexpectedMessage.into()),
        }
    }
}
