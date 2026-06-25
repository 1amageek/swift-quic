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

## Status: Slice B rails landed (engine-driven path is additive)

The cored orchestration engine `QUICConnectionEngine<C, T>` (target
`QUICConnectionEngineCore`) is now driven by a seam-based facade alongside the
proven host orchestrator:

- `FacadeLock.swift` — host `Synchronization.Mutex` typealias / Embedded
  `Atomic<Bool>` spinlock (verbatim from the proven swift-tls Tier-1 facade).
- `AsyncTimerClock.swift` — the host `AsyncTimer` (`ContinuousClock`+`Task.sleep`),
  the engine's `T` clock seam (host-gated; Embedded injects its own `AsyncTimer`).
- `QUICEngineConnection.swift` — the `final class & Sendable` driver holding
  `FacadeLock<QUICConnectionEngine>` over the `DatagramTransport` (UDP) +
  `AsyncTimer` (clock+sleep) seams. It inverts I/O (`transport.incoming →
  engine.receive → transport.send`) and drives the clock-free timer loop (read
  `deadlines(nowNanos:)`, `sleep(untilNanos: earliest)`, on wake
  `handleTimeout(nowNanos:)`). No `ContinuousClock`/`Task.sleep`/`Date` in the
  driver — all time flows through the injected `AsyncTimer`.
- `QUICEngineConfigurationStrategy.swift` — host vs Embedded crypto/cert capability
  behind one signature: host CSPRNG + injected X.509 validator (fail-closed);
  Embedded RPK (RFC 7250) leaf-SPKI parsing via `P2PCoreDER` (fail-closed).

The driver is wired and unit-tested end-to-end (`QUICEngineConnectionTests`:
stream round-trip + close over an in-memory loopback transport), but it is NOT yet
the live data path: `QUICEndpoint`/`ManagedConnection` keep their proven
`QUICConnectionHandler`/`PacketProcessor` spine so the public Foundation/NIO API
and the 895 host tests stay intact. Now-internal orchestrators (`PacketProcessor`,
`ConnectionRouter`, `TimerManager`/`TimerWheel`) are demoted to `package`.

## Embedded gate (the milestone): `--target QUIC -c release` COMPILES (quic Slice C)

The `QUIC` target is now DUAL-BUILD via the proven swift-tls Slice B route
(currency + Foundation-gating; the host spine is NOT rewritten):

- **Host spine gated host-only.** `QUICEndpoint` / `ManagedConnection` /
  `ManagedStream` / `QUICConnection` (the Foundation-`Data` `QUICStreamProtocol`
  + NIO `SocketAddress` bridge) / `QUICConfiguration` / `PacketProcessor` /
  `ConnectionRouter` / `TimerManager` / `VersionNegotiator` are each wrapped
  whole in `#if !hasFeature(Embedded)`. The public host API
  (`QUICEndpoint` / `ManagedConnection` / `QUICConnectionProtocol` /
  `QUICStreamProtocol` / `QUICConfiguration` / `QUIC.SocketAddress`) is UNCHANGED,
  so swift-libp2p builds unchanged.
- **Conditional dependencies.** `Package.swift`'s `quicFacadeDependencies` drops
  the host adapter targets (`QUICCore` / `QUICCrypto` / `QUICConnection` /
  `QUICStream` / `QUICRecovery` / `QUICTransport` + `Logging`) under
  `P2P_CORE_EMBEDDED=1`; the `QUIC` target carries `swiftSettings: coreSettings`.
- **The Embedded surface** is the `[UInt8]`/`SocketEndpoint` facade: the cored,
  sans-IO `QUICEngineConnection` driver plus the public concrete
  `QUICEngineClient` (pinned to `DefaultCryptoProvider`) over it, with the
  dual-build seams `FacadeLock` / `AsyncTimerClock` (host-gated impl) /
  `QUICEngineConfigurationStrategy` (host X.509 vs Embedded RPK, fail-closed).

Phase-2 features (Retry / 0-RTT / connection-migration / peer-initiated
key-update live-wiring) are DEFERRED — the engine drops/does-not-wire them and the
facade surfaces them as a typed throw (`QUICEngineError.invalidState`), never a
silent fallback.

## Build

- Host: `swift build` / `swift test --skip QUICBenchmarks`. The full Foundation/NIO
  spine compiles; `QUICEngineClient` / `QUICEngineConnection` compile alongside it.
- Embedded (the milestone): `P2P_CORE_EMBEDDED=1 P2P_CRYPTO_EMBEDDED=1
  swiftly run +6.3.1 swift build --target QUIC -c release`. Only the cores + the
  `[UInt8]` engine facade compile; the host spine is gated away.
