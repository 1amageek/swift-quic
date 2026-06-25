# QUICConnectionEngineCore — CONTEXT
Scope/role: the cored, Embedded-clean QUIC connection orchestrator (`QUICConnectionEngine<C, T>`); the substrate the host `QUIC` facade will drive once Slice B rewires it. Drives the other six cores.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing the engine seam or its timer surface. This is the QUIC analogue of
swift-tls's `DTLS*Engine<C>`: it owns the per-connection orchestration that the
host `ManagedConnection` currently performs under `Mutex`, but as a pure value
type with no lock and no I/O. The byte currency is `[UInt8]` / `Bytes`.

## Contracts (the load-bearing rules)

- **Value type, caller-locked, sans-IO.** `QUICConnectionEngine<C, T>` is a
  `struct` with `mutating` methods. It holds NO lock and performs NO socket I/O.
  The host facade is "the caller that locks": it holds the engine behind a
  `FacadeLock` and serialises every mutation. Do NOT add a lock inside the engine,
  and do NOT make it a reference type.
- **I/O is inverted to the facade.** Inbound is `receive(datagram:from:nowNanos:)
  -> QUICEngineOutput`; outbound bytes are produced as `datagramsToSend` in the
  output / timer output. The facade owns the `DatagramTransport` (UDP) and
  `AsyncTimer`. The engine consumes and produces bytes only.
- **Clock-free timers (mirror DTLS).** No `ContinuousClock` / `Task.sleep` /
  `Date`. Time enters ONLY as an injected `nowNanos: UInt64`. `deadlines(nowNanos:)`
  reports the absolute deadline set (loss/PTO, ACK delay, idle, path validation,
  pacing); the facade parks its `AsyncTimer` against the earliest. On wake the
  facade calls `handleTimeout(nowNanos:)`, which drives every elapsed timer and
  returns what to send plus the recomputed deadlines. This is the analogue of
  DTLS's `DTLSFlightController` + `handleTimeout()`.
- **It drives the cores; it does NOT reimplement them.** Packet-number spaces over
  `PacketNumberSpace` numbering; `LossDetectorCore` + `RTTEstimatorCore` +
  `CubicCore` + `PacerCore` + `AntiAmplificationCore` for recovery;
  `SendStreamCore` / `ReceiveStreamCore` / `FlowControllerCore` (via
  `QUICStreamSet`) for streams; `IdleTimeoutCore`; `PathValidationCore`; and
  `PacketParsingCore` over `SuiteProtector<C>`. Fixes to protocol behaviour belong
  in the relevant core, not duplicated here.
- **`T: MonotonicClock` is a phantom parameter.** The engine never touches `T`; it
  documents the facade's clock dependency and keeps the type shape aligned with
  the future `Facade<C, T>`.
- **Crypto/cert capability is injected, X.509 stays out.** `randomBytes` (CSPRNG)
  and `validateCertificate` (peer trust) are `@Sendable` typed-throws closures on
  `QUICConnectionEngineConfiguration<C>`. Only DER bytes cross the boundary — no
  X.509 types enter the engine. The facade fills them (host bridge vs Embedded RPK
  strategy).

## Invariants (must hold; tests guard them)

- **Decryption failure on a single packet is NON-fatal — drop, never throw.** A
  packet that fails to decrypt with the current keys is dropped per RFC 9001 §5.5;
  throwing would let an attacker kill the connection by injecting one bad packet.
  This is the one place the engine deliberately does not surface a typed error.
- **Authentication and protocol violations DO throw (no silent fallback).** A
  failed CertificateVerify possession check, a thrown injected
  `validateCertificate` (fail-closed peer trust), a flow-control / final-size /
  stream-limit violation, packet-number-space exhaustion (2^62, RFC 9000 §12.3),
  or a malformed transport parameter all surface as a typed `QUICEngineError`. The
  caller (facade) decides whether to close. `validateCertificate` runs AFTER the
  in-core possession check and is fail-closed: a throw aborts the connection, so a
  peer identity never surfaces unverified.
- **Idle timeout is terminal, not self-closing.** On idle expiry `handleTimeout`
  sets `idleExpired` and returns; the facade tears the connection down. The engine
  does not silently self-close.
- **PTO sends an ack-eliciting probe** (RFC 9002 §6.2.4): on PTO the engine bumps
  `ptoCount` (bounded backoff `2^min(ptoCount, 20)`, saturating) and queues a PING
  so flush emits an ack-eliciting packet.
- **Key state honours RFC 9001.** Initial keys are AES-128-GCM derived from the
  original destination CID; handshake/application keys install from traffic
  secrets with the negotiated `QUICProtectionSuite`; 1-RTT key update derives the
  next generation for both directions and flips the key phase
  (`QUICKeyState.initiateKeyUpdate`). A request for a missing level's protector
  throws `keysUnavailable` rather than dropping silently.

## Embedded constraints (do not regress)

- No Foundation, no `any` existentials, no `Mutex`, no `ContinuousClock`, no
  direct crypto library. Generics over `C: CryptoProvider`; cipher-suite dispatch
  is the closed `SuiteProtector<C>` enum.
- Single typed error `QUICEngineError` (every fallible entrypoint is
  `throws(QUICEngineError)`); the facade maps it to its public error inside the
  lock, mirroring `DTLSEngineError → TLSError`. A cross-type `catch` (e.g. folding
  a core error) must live in a NAMED function, never a closure literal.

## Dependencies & seams

- Injected closures: `randomBytes` (CSPRNG) and `validateCertificate` (fail-closed
  peer trust returning an optional opaque peer identifier).
- `C: CryptoProvider` for all key derivation / AEAD / header protection;
  specialised by the facade at `C = QUICCryptoProvider`.

## Status: not yet driven by the facade (Slice B pending)

This core compiles green Embedded (`P2P_CORE_EMBEDDED=1 swift build --target
QUICConnectionEngineCore -c release`), but the host orchestrator (`QUICEndpoint` /
`ManagedConnection` / `TimerManager`) is NOT yet rewired onto it. The facade
rewire (`FacadeLock<Engine>` + `AsyncTimer` + `DatagramTransport` driver, and the
`--target QUIC -c release` full Embedded compile) is the pending "quic Slice B"
follow-up (ROADMAP M11).

## Build

- Host: `swift build` / `swift test --filter QUICConnectionEngineCoreTests`.
- Embedded: `P2P_CORE_EMBEDDED=1 swift build --target QUICConnectionEngineCore -c release`.
