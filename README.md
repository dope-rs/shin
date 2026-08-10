# 神 (shin)

`shin` is a sans-I/O, thread-per-core TLS 1.3 implementation. It owns the
protocol state machine and cryptography; the embedder owns sockets, scheduling,
TLS record transport (or QUIC CRYPTO frames), buffers, timers, and policy.

The public transport choice is explicit. `Client::new` and `Server::new` are
TLS-over-stream constructors. QUIC integrations must use
`new_with_transport(..., Mode::Quic, ...)`; empty transport parameters
do not imply TLS. See the [architecture and production guide](docs/architecture.md)
before integrating either mode.

## Sans-I/O driving

The state machine emits events synchronously. Bytes in `Send`, `PeerExtension`,
and `NewSessionTicket`, as well as secret-bearing event values, borrow
protocol-owned/input storage. Consume them inside `EventSink::event`; make an
explicit copy into suitable owned, zeroizing storage only when retention is
required.

```rust
use core::convert::Infallible;
use shin::client::Client;
use shin::connection::{Clock, DriveError, Epoch, Event, EventContext, EventSink};

#[derive(Default)]
struct ReactorEvents {
    outbound: Vec<(Epoch, Vec<u8>)>,
    done: bool,
}

impl EventSink for ReactorEvents {
    type Error = Infallible;

    fn event(
        &mut self,
        event: Event<'_>,
        _context: EventContext,
    ) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => {
                // `data` is borrowed only for this callback.
                self.outbound.push((epoch, data.to_vec()));
            }
            Event::Done => self.done = true,
            // A production sink also installs KeysReady/KeyUpdate secrets,
            // forwards PeerExtension to QUIC, and persists ticket events.
            _ => {}
        }
        Ok(())
    }
}

fn start<C: Clock>(
    client: &mut Client<C>,
    events: &mut ReactorEvents,
) -> Result<(), DriveError<Infallible>> {
    client.start_into(events)
}

fn feed_decrypted_handshake<C: Clock>(
    client: &mut Client<C>,
    epoch: Epoch,
    bytes: &[u8],
    events: &mut ReactorEvents,
) -> Result<(), DriveError<Infallible>> {
    client.read_into(epoch, bytes, events)
}
```

For TLS, frame/protect each `Send` with the record API and pass decrypted record
payloads back to `read_into`. For QUIC, map epochs to QUIC encryption levels and
carry the same handshake bytes in CRYPTO frames. Process events in emission
order: in particular, send a KeyUpdate with the old write key before installing
the following `KeyUpdate { direction: Write, .. }` secret.

## Implemented cryptography

- Cipher suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, and
  TLS_AES_256_GCM_SHA384.
- Key exchange groups: X25519, secp256r1 (P-256), and X25519MLKEM768. The client
  defaults to X25519. `Client::set_kex_group` is the compact compatibility
  path; `Hybrid` plus caller-owned `kx::HybridWorkspace` removes the
  hybrid ephemeral heap allocation.
- Raw-public-key and X.509 authentication, session tickets, TLS 0-RTT, mutual
  TLS, ALPN, exporters, HelloRetryRequest, and TLS KeyUpdate are supported.

API entry points are in [the client module](src/client/mod.rs),
[the server module](src/server/mod.rs), [connection events](src/connection.rs),
[transport mode](src/transport.rs), and [the record layer](src/wire/record/mod.rs).
Operational invariants, memory profiles, 0-RTT replay requirements, limits, and
verification commands are collected in the
[architecture and production guide](docs/architecture.md).

© 2026 inkyu
