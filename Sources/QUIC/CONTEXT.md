# QUIC — CONTEXT
Scope/role: the host orchestrator and public entry point (`QUICEndpoint` / `ManagedConnection` / `ManagedStream`); the Foundation facade callers import.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing the I/O loop, key installation, or the connection lifecycle. This
is a host-only module: it owns the UDP I/O loops, the per-connection async
orchestration, and the public high-level API. It is NOT yet ported to the cored
engine (see status below).

## Contracts (the load-bearing rules)

- **Cipher-suite dispatch goes through the cored seam.** `PacketProcessor`
  encryption/decryption selects the cipher suite via `SuiteProtector<C>` (a closed
  enum, `C = QUICCryptoProvider`), NOT `any PacketOpener` / `any PacketSealer`.
- **Key installation must propagate the negotiated cipher suite.** Take
  `cipherSuite` from `KeysAvailableInfo`, derive `KeyMaterial` with it, and build
  the protector via the key-derivation factory. Never hardcode AES-128-GCM on the
  install path — that silently breaks ChaCha20-Poly1305 connections.
- **The I/O loop must be cancellation-clean.** `run(socket:)` wraps its task group
  in `withTaskCancellationHandler` and stops the socket on cancel; the socket's
  `shutdown()` MUST `finish()` the incoming-packet continuation. Without this,
  `for await packet in socket.incomingPackets` blocks forever and `shutdown()`
  hangs. (See AsyncStream rule: a type vending an AsyncStream must implement
  `shutdown()` that finishes the continuation.)

## Invariants (must hold; tests guard them)

- **A TLS provider is mandatory — no insecure default.** Configuration is via
  `.production` / `.development` (caller supplies a provider) or `.testing`
  (`MockTLSProvider`, DEBUG-guarded). There is no path that runs without one.
- **Graceful shutdown prevents continuation leaks.** `shutdown()` and `close()`
  guard against concurrent/duplicate calls; `start()` / `startWith0RTT()` is an
  atomic state transition (double-start prevention).
- **Fail-closed peer authentication** is enforced through the crypto/TLS layer:
  CertificateVerify is always verified and Finished is accepted only after
  authentication; the facade never exposes an unauthenticated connection.

## Packet flow

- Inbound: UDP datagram → `CoalescedPacketParser.parse` (split coalesced packets)
  → `PacketProcessor.decryptPacket` (extract header info, pick the per-level
  `CryptoContext`, remove header protection, AEAD-open) → parsed frames.
- Outbound: frames + header → `PacketProcessor.encrypt{Long,Short}HeaderPacket`
  (AEAD-seal, apply header protection) → encrypted packet → coalesce → send.
- Encryption levels (packet-number spaces): Initial, 0-RTT (client only),
  Handshake, Application (1-RTT short header).

## Status: not yet rewired onto the cored engine (Slice B pending)

The cored orchestration engine `QUICConnectionEngine<C, T>` (target
`QUICConnectionEngineCore`) exists and compiles green Embedded, but the host
orchestrator here — `QUICEndpoint`, `ManagedConnection` (~2257 lines),
`TimerManager` — does NOT yet drive it. The facade rewire (`FacadeLock<Engine>` +
`AsyncTimer` + `DatagramTransport` driver, and the `--target QUIC -c release`
Embedded compile) is the pending "quic Slice B" follow-up (ROADMAP M11). Until
then the Embedded compile covers the cores, not this facade. The public API
(`QUICEndpoint.serve/dial`, `QUICConfiguration.production`, `MockTLSProvider`) is
unchanged and accurate.

## Build

- Host only: `swift build` / `swift test --filter QUICTests`. This module is not
  yet part of the Embedded compile.
