# Architecture and production guide

This document describes the contracts an embedder must uphold around `shin`'s
sans-I/O state machines. It documents the current public API; it is not a
network-stack abstraction.

## Ownership and drive model

A `Client`, `Hybrid`, `Server`, or `Shard` belongs to one event loop for
its entire lifetime. These types are intentionally neither `Send` nor `Sync`.
Construct, drive, and drop them on the owning core; exchange socket ownership
or plain configuration data at thread boundaries instead of moving live TLS
state.

The clock passed to a connection implements `Clock` and returns wall-clock
milliseconds since the UNIX epoch. It is used for certificate and ticket time
checks and must be accurate enough for those policies.

The drive boundary is:

1. A client calls `Client::start_into`; a server starts when its first
   `Server::read_into` receives a ClientHello.
2. TLS integrations open a record and pass its handshake payload and `Epoch` to
   `read_into`. QUIC integrations pass ordered CRYPTO bytes at the corresponding
   encryption level. Fragmented and coalesced handshake messages are accepted
   within an epoch.
3. The sink consumes every event synchronously. `Send`, `PeerExtension`, ticket
   nonce, and ticket bytes are borrowed only for the callback. Copy bytes that
   must outlive it. Secret-bearing events also borrow protocol-owned,
   purpose-specific secret types; install them synchronously or explicitly copy
   them into an owned zeroizing container.
4. `EventContext::cipher_suite` identifies the negotiated suite when available.
   Install `KeysReady` read/write secrets into the matching record or QUIC key
   slots, handle `KeyUpdate` in event order, and treat `Done` as handshake
   completion rather than socket completion.

`Event::Send` contains TLS handshake messages, not socket-ready data. A stream
TLS embedder wraps plaintext or encrypted handshake bytes in TLS records using
the indicated epoch. A QUIC embedder puts them in CRYPTO frames and owns packet
protection, loss recovery, and QUIC key-phase updates.

## TLS and QUIC are explicit modes

| Contract | TLS over a stream | QUIC |
| --- | --- | --- |
| Client constructor | `Client::new` / `with_transport_workspace(..., Mode::Tls, ...)` | `Client::new_with_transport(..., Mode::Quic, ...)` / `with_transport_workspace` |
| Server constructor | `Server::new` / `with_workspace` | `Server::new_with_transport(..., Mode::Quic, ...)` / `with_transport_workspace` |
| Transport parameters | Must be empty | Opaque bytes; may legitimately be empty |
| Handshake carrier | TLS records | QUIC CRYPTO frames |
| Legacy session ID and EndOfEarlyData | Used as required by TLS | Omitted |
| Post-handshake key update | `send_key_update_into` and peer KeyUpdate | Owned by QUIC; TLS KeyUpdate is rejected |
| 0-RTT ticket marker | Nonzero finite byte limit | `u32::MAX`, as required by QUIC TLS mapping |

Never infer the mode from whether transport parameters are empty. Validate
client configuration with the same mode used by its constructor. Validate both
the server's endpoint `Config` and per-connection `Connection` before accepting
traffic; use `Connection::validate_with_transport` for QUIC.

## Terminal failure semantics

`DriveError` distinguishes a protocol failure (`DriveError::Protocol`) from an
embedder callback failure (`DriveError::Sink`). A fatal failure while driving a
connection poisons it. Retain the original error for diagnostics or alert
mapping, tear down the transport, and do not retry input or continue emitting
events; subsequent drives return `Error::ConnectionFailed`.

A sink failure is terminal too: some earlier events from the same call may
already have been observed, so replaying the call cannot be transactional.
Authentication failures and record open failures are likewise fatal. Record
`Opener` permanently rejects use after an authentication or parse failure.
`Event`'s `Debug` implementation redacts secrets, but applications must still
avoid logging raw secret or ticket buffers.

Constructor and sequencing precondition errors should be fixed by the caller,
not used as a recovery mechanism. In production, treat every returned drive
error as requiring connection disposal.

## Server shards and thread-per-core deployment

Create one `Shard` per owning event loop/core. A `Server` binds to the identity
of the `Shard` supplied on its first `read_into`; passing another `Shard` later
permanently fails that connection. This prevents connection-local state from
silently switching endpoint policy, certificate identity, ticket keys, replay
guard, or client-auth verifier.

Rotate ticket keys in place with `Shard::replace_ticket_keys` instead of
replacing the `Shard` used by live connections. Provision coordinated ticket
key generations to all shards or nodes that must accept one another's tickets,
and retain old decrypt keys for the intended overlap. New connections may use a
new shard generation; an existing `Server` must continue with its first shard.

## Resumption and 0-RTT

Ticket resumption and permission to transmit early data are deliberately
separate:

- Persist the borrowed `ResumptionSecret` PSK in a zeroizing owner and associate
  it, by event order, with the corresponding `NewSessionTicket` fields. Copy
  the borrowed ticket bytes in the callback.
- `Resumption::new` enables PSK resumption without 0-RTT authority.
- Use `Resumption::new_with_early_data` only when that ticket advertised
  `max_early_data`, passing the same explicit `Mode`. Also set the
  client configuration's `enable_early_data` flag. A mode/limit mismatch does
  not authorize early data.
- On the client, do not treat an early write as committed until
  `EarlyDataAccepted` is observed; retransmit it according to application
  policy after `EarlyDataRejected`.

At reconnect time, construct the entitlement from the copied event values and
the ticket's current age in milliseconds:

```rust
let resumption = shin::client::config::Resumption::new_with_early_data(
    *saved_psk.as_array(),
    ticket,
    ticket_age_add,
    age_millis,
    max_early_data,
    transport_mode,
);
```

Here `saved_psk` is a caller-owned `ResumptionPsk` created explicitly from the
borrowed event value; the array copy is consumed immediately by `Resumption`.
Use `Resumption::new(psk, ticket, ticket_age_add, age_millis)` when the ticket
did not advertise early data or the application chooses not to use it.

Server 0-RTT is disabled by the default `NoGuard`. To enable it, construct the
shard with `Shard::with_early_data_guard` (or the combined client-auth
constructor) and implement `EarlyDataGuard::register` as an atomic single-use
check.

The replay namespace must cover every core, process, host, and region able to
decrypt the same ticket key generation. A per-shard in-memory set is not a
production replay defense when ticket keys are shared. Retain tokens for the
full issued ticket lifetime (currently 7,200 seconds), make the check atomic
across that namespace, and fail closed if the replay service is unavailable.
Even with a guard, only replay-safe/idempotent application operations belong in
0-RTT.

Before delivering each decrypted early-data chunk, call
`Server::note_early_data(len)`. `Server::max_early_data_size` reports the open
budget. Exceeding or charging a closed window returns
`EarlyDataLimitExceeded` and permanently fails the connection.

## Workspace and allocation profiles

Handshake storage is caller-recyclable through `Scratch`:

- `Scratch::for_client` and `Scratch::for_server` are lazy-growth defaults.
  They reserve one 16 KiB plaintext record for reassembly and one for the
  outbound flight: two allocations and 32 KiB at construction. Their logical
  handshake/flight limits are 256 KiB, so unusually large flights can allocate
  while growing. The server peer-identity region also has a 256 KiB logical
  limit but starts unreserved; the client identity region is unused.
- `Scratch::new(fragmented, outbound, peer_identity)` fully reserves the three
  caller-selected limits. Supply it through client `with_transport_workspace`
  or server `with_workspace`, together with preallocated event and record
  buffers, for the covered no-allocation handshake and record paths. Undersizing fails with a typed
  `WorkspaceExhausted` error instead of exceeding the logical limit.
- `into_workspace` clears and returns storage for reuse by the same owning
  core. Do not pool live protocol objects across threads.

Size the fragmented-message and outbound-flight regions from measured maximum
certificate chains/extensions, and the server peer-identity region from the
maximum accepted client chain. The protocol maximum is 256 KiB and a
Certificate message is limited to 16 entries. Allocation regression tests
cover classical/RPK and X.509 handshake paths and caller-owned record paths.

Hybrid client key exchange has two explicit profiles:

- Ordinary `Client::set_kex_group(X25519Mlkem768)` is the compatibility path.
  It preserves the compact 4,032-byte `Client`, 120-byte `Scratch`, and
  144-byte `EphemeralKey` layouts, and performs one allocation for the large
  hybrid ephemeral state.
- `Hybrid` borrows a caller-owned `crypto::kx::HybridWorkspace` for its
  entire lifetime. The 3,272-byte workspace holds ML-KEM and X25519 private
  state inline, while the wrapper itself is only 4,040 bytes. With preallocated
  `Scratch`, event, and record buffers, the measured full hybrid handshake has
  zero heap allocations and does not regenerate ML-KEM state.

The exclusive workspace borrow prevents concurrent clients from sharing a
slot or separating an in-place key token from its storage. After successful
agreement the slot is consumed. After a failed drive it is cleared; if a
wrapper is dropped earlier, the next bound client clears stale state before
generation, and dropping the workspace zeroizes its remaining ML-KEM key.
Reuse one workspace sequentially on its owning core, never concurrently.

## Record and key lifecycle

TLS plaintext is limited to 16 KiB and ciphertext bodies to 16 KiB plus 256
bytes. `Sealer` and `Opener` enforce a common per-key record limit of 2^23 and
report `KeyLimitReached`; use `needs_key_update` and rotate before attempting
the next record at the limit. A failed `Opener::open` poisons that opener.

TLS KeyUpdate handling has two independent abuse bounds: at most eight
KeyUpdate messages in one supplied record and at most eight consecutive peer
updates without application-data progress. Call `Client::note_application_data`
or `Server::note_application_data` exactly once after each successfully
decrypted application-data record so real progress resets the second budget.

Respect emitted ordering. For a locally initiated update, protect and enqueue
the `Send { epoch: Application, .. }` message with the old write key, then
install the following write-direction secret. Install read-direction secrets
when their `KeyUpdate` event arrives. These TLS rules do not apply to QUIC;
drive QUIC key phases in the QUIC stack.

## Supported negotiation

Cipher-suite preference order is:

1. TLS_AES_128_GCM_SHA256
2. TLS_CHACHA20_POLY1305_SHA256
3. TLS_AES_256_GCM_SHA384

Supported key exchange groups are X25519, secp256r1 (P-256), and
X25519MLKEM768. Clients offer X25519 by default and can choose one supported
group with `Client::set_kex_group` before starting. They can restrict cipher
suites with `Client::set_cipher_suites` before starting.

## Production checklist

- Choose TLS or QUIC explicitly and validate configuration for that same mode.
- Validate certificate chains, signing-key matches, trust anchors, server name,
  ALPN, transport-parameter lengths, and ClientHello size during startup.
- Keep every client, server, template/shard, resumption object, and live secret
  on its owning core. Preserve the first-shard binding for each server.
- Supply UNIX-epoch milliseconds from a trustworthy clock and monitor clock
  skew because certificate, ticket-age, and 0-RTT checks depend on it.
- Consume every event synchronously, copy borrowed values that must persist,
  install traffic secrets in order, and never log them.
- Dispose of the connection after any drive/sink/record error; preserve the
  first error for metrics and alert policy.
- For TLS, enforce record size/key limits and call `note_application_data`. For
  QUIC, leave packet protection and key phases to the QUIC stack.
- Keep 0-RTT off unless a global atomic replay guard and replay-safe application
  policy are deployed. Charge every accepted early-data byte before delivery.
- Rotate ticket keys in place on live shards and coordinate key/replay domains
  across every worker that accepts the tickets.
- Select the lazy Scratch profile for low idle memory or fully reserve measured
  caller-owned capacities for deterministic allocation behavior. Recycle with
  `into_workspace`.
- For X25519MLKEM768, choose the compact compatibility client (one ephemeral
  allocation) or bind `Hybrid::from_client` to a sequentially reused
  `HybridWorkspace` for a fully caller-owned, zero-allocation handshake.
- Run tests, allocation checks, benchmarks, and fuzz targets on the production
  feature/toolchain matrix before release.

## Verification commands

From the repository root:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features

# Allocation and bounded-resource regressions under optimized code.
cargo test --release --test handshake_zero_alloc --test record_zero_alloc --test resource_profiles

# Release-mode performance ceiling harness; increase repetitions when needed.
cargo bench --bench perf_ceiling
SHIN_BENCH_SCALE=4 cargo bench --bench perf_ceiling

# Fuzz package build and representative runs (requires nightly + cargo-fuzz).
cargo check --manifest-path fuzz/Cargo.toml --bins
cargo +nightly fuzz run handshake_parse -- -max_total_time=60
cargo +nightly fuzz run conn_read -- -max_total_time=60
cargo +nightly fuzz run record_parse -- -max_total_time=60
cargo +nightly fuzz run cert_parse -- -max_total_time=60
cargo +nightly fuzz run chain_validate -- -max_total_time=60
cargo +nightly fuzz run ticket_decrypt -- -max_total_time=60
```

The benchmark reports object/workspace profiles plus full and resumed RPK
handshakes, HelloRetryRequest, one/two/four-entry X.509 chains, record sizes from
0 through 16 KiB, and all three key-exchange groups. Treat its output as a
descriptive baseline for the same host and build, not a cross-machine score.

The remaining fuzz targets are listed in [the fuzz manifest](../fuzz/Cargo.toml).
Allocation expectations live in
[handshake_zero_alloc](../tests/handshake_zero_alloc.rs),
[record_zero_alloc](../tests/record_zero_alloc.rs), and
[resource_profiles](../tests/resource_profiles.rs).
