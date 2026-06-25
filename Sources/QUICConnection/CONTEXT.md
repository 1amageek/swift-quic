# QUICConnection — CONTEXT
Scope/role: the host (Foundation) per-connection state machine and TLS integration (`QUICConnectionHandler`); a thin adapter over `QUICConnectionCore`.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing key installation or the TLS integration flow. `QUICConnectionHandler`
is a host adapter; the pure connection state machines (neither codec nor crypto)
live in the Embedded-clean `QUICConnectionCore` value types.

## Contracts (the load-bearing rules)

- **The state machines live in the core, not here.** `ConnectionStateCore`,
  `IdleTimeoutCore`, `PathValidationCore`, `PathMTUSearchCore` (DPLPMTUD,
  RFC 8899 / RFC 9000 §14), `TransportParameterCodecCore` + `IPAddressCodec`
  (transport-params codec, RFC 9000 §18, Foundation-free IPv4/IPv6 parser), and
  `PacketParsingCore` (driving `SuiteProtector<C>`) are all in `QUICConnectionCore`.
  Behaviour fixes belong there.
- **Key installation must propagate the negotiated cipher suite.** Take
  `cipherSuite` from `KeysAvailableInfo`, derive read/write `KeyMaterial` with it,
  and build protectors via the key-derivation factory. Never hardcode AES-128-GCM —
  it silently breaks ChaCha20-Poly1305. Cipher-suite dispatch is `SuiteProtector<C>`
  (closed enum), not `any PacketOpener` / `any PacketSealer`.
- **Read vs write key direction is role-dependent.** Client reads with the server
  secret and writes with the client secret; server is the mirror. 0-RTT is
  unidirectional (client write / server read).

## Invariants (must hold; tests guard them)

- **Fail-closed peer authentication.** CertificateVerify is always verified; a
  server cannot skip Certificate/CertificateVerify, and Finished is accepted only
  after authentication completes (no unauthenticated/MITM channel).
- **TLS output is acted on, not dropped.** `TLSOutput.keysAvailable` installs keys
  (with the cipher suite), `.handshakeComplete` advances to connected, `.error`
  closes the connection. A `.handshakeData` output is queued for send at its level.
- **Transport-parameter ↔ Connection-ID cross-validation (RFC 9000 §7.3):**
  `initial_source_connection_id` / `original_destination_connection_id` /
  `retry_source_connection_id` are checked against the CIDs observed during the
  handshake; a mismatch is TRANSPORT_PARAMETER_ERROR.

## Build

- Host only: `swift build` / `swift test --filter QUICConnectionTests`. The
  underlying `QUICConnectionCore` is part of the Embedded compile.
