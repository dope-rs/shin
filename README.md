# 神 (shin)

`shin` is a sans-I/O, thread-per-core TLS 1.3 implementation. It owns the
protocol state machine and cryptography; the embedder owns sockets, scheduling,
TLS record transport (or QUIC CRYPTO frames), buffers, timers, and policy.

The public transport choice is explicit. `Client::new` and `Server::new` are
fallible TLS-over-stream constructors, so invalid configuration never becomes
runtime state. QUIC integrations must use
`new_with_transport(..., Mode::Quic, ...)`; empty transport parameters
do not imply TLS.

## Sans-I/O driving

The state machine emits events synchronously. Bytes in `Send` and
`PeerExtension`, the fields of the client-side `Ticket`, and secret-bearing event values
borrow protocol-owned/input storage. Consume them inside `EventSink::event`.
Ignoring a session ticket performs no PSK derivation or allocation;
`Ticket::try_retain` derives the PSK, copies the opaque identity once,
and returns an owned resumption bound to the endpoint that issued it.

```rust
use shin::client::Client;
use shin::client::config::{self, Resumption};
use shin::connection::{Clock, DriveError, Epoch, Event, EventContext, EventSink};

#[derive(Default)]
struct ReactorEvents {
    outbound: Vec<(Epoch, Vec<u8>)>,
    resumption: Option<Resumption>,
    done: bool,
}

impl EventSink for ReactorEvents {
    type Error = config::Error;

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
            Event::NewSessionTicket(ticket) => {
                self.resumption = Some(ticket.try_retain()?);
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
) -> Result<(), DriveError<config::Error>> {
    client.start_into(events)
}

fn feed_decrypted_handshake<C: Clock>(
    client: &mut Client<C>,
    epoch: Epoch,
    bytes: &[u8],
    events: &mut ReactorEvents,
) -> Result<(), DriveError<config::Error>> {
    client.read_into(epoch, bytes, events)
}
```

Pass a retained value to `Client::resume` for the next connection; it reuses
the validated endpoint and transport automatically. For persistence,
`Ticket::try_psk` derives the PSK while the ticket identity, ALPN, suite, mode,
and timing remain borrowed for direct serialization. Loading constructs a
`config::Restore`, explicitly supplies the issuing connection's exact ALPN
(`NegotiatedAlpn::Absent` is authoritative), then calls `Template::restore`.
That boundary moves an owned ticket without copying, resolves borrowed or owned
ALPN bytes to a compact endpoint-local ID, and drops only 0-RTT authority when
the stored profile does not fit the current endpoint. `Config` contains reusable
policy only; unresolved persistence state cannot enter a `Client` directly.

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

© 2026 inkyu
