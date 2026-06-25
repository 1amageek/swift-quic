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

## Embedded gate (the milestone): `--target QUIC -c release` does NOT compile

This is the irreducible blocker, identical in shape to swift-tls's Slice B: the
public facade surface is Foundation `Data` (`QUICStreamProtocol.read()->Data` /
`write(Data)`) and NIO-bridging (`QUIC.SocketAddress.init(_ nioAddress:)` /
`toNIOAddress()`), and `QUIC` hard-depends on the host adapters `QUICCore`
(→`P2PCoreFoundation`/Foundation), `QUICCrypto` (→X509/SwiftASN1/Crypto/Foundation),
`QUICConnection`, `QUICStream`, `QUICRecovery`, `QUICTransport` (→NIO). swift-libp2p
is pinned to those exact symbols, so they cannot be gated away. The first failure
is `P2PCoreFoundation` importing the Embedded-built `P2PCoreBytes` under Foundation.
A full Embedded `QUIC` compile requires a NEW Foundation-free facade product (a
`[UInt8]`/`SocketEndpoint` surface over `QUICEngineConnection`) — a follow-up
slice. The cores, incl. `QUICConnectionEngineCore`, still compile Embedded.

## Build

- Host: `swift build` / `swift test --skip QUICBenchmarks`. The seam driver
  (`QUICEngineConnection`) is dual-build-shaped (cores + seams only); the facade
  module is host-only until the Foundation-free facade product lands.
