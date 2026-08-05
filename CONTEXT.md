# swift-quic — CONTEXT
Scope/role: a pure-Swift QUIC implementation (RFC 9000/9001/9002) used as the libp2p QUIC transport; the public surface is the host `QUIC` facade, layered over a set of Embedded-clean cores.
Last reviewed: 2026-07-31

Invariants and design intent the source does not state structurally. Read this
before changing the tier split, the crypto seam, or any core. swift-quic is
**Embedded-first**: the protocol logic lives in value-type, sans-IO *core*
targets generic over the crypto seam, and the host (Foundation) modules are thin
adapters over them. The byte currency in the cores is `[UInt8]` / `Bytes`; there
is no backward-compatibility obligation to the old `Data` API inside a core.

## Target TLS boundary

- `swift-quic` is the sole owner of QUIC CRYPTO offsets/reassembly, transport
  parameters, packet/header protection, key installation, packet-number spaces,
  recovery, congestion control, streams, and datagram orchestration.
- The target handshake dependency is
  `swift-quic -> swift-tls-sessions/QUICTLS -> swift-ssl`. `swift-tls-sessions`
  owns the public QUIC TLS session contract; `swift-ssl` owns the TLS 1.3 transcript, key
  schedule, handshake messages, authentication mechanisms, and emitted traffic
  secrets.
- The former `QUICTLSCore` and `TLS13Handler` implementation and test sources
  have been removed. There is no compatibility target or active consumer for
  that design.
- Moving the TLS state machine must not move CRYPTO frame offset handling or
  reassembly out of `swift-quic`.

See the workspace
[`SECURE_TRANSPORT_ARCHITECTURE.md`](../../SECURE_TRANSPORT_ARCHITECTURE.md).

## Tier model (why, not just what)

- **Cores (Embedded-clean, dual-build).** Value-type, caller-locked, sans-IO
  building blocks generic over `C: CryptoProvider`. They compile both as ordinary
  host libraries and under Embedded Swift. The seven cores:
  - `QUICWire` — Tier-3 wire codec (varint, frame/packet codecs, version
    constants). No crypto, no I/O.
  - `QUICPacketProtectionCore` — `PacketProtector<C, A>` (AEAD + header protection
    over the seam) and the closed `SuiteProtector<C>` cipher-suite enum.
  - `QUICRecoveryCore` — loss detection, CUBIC/NewReno, pacing, anti-amplification.
  - `QUICStreamCore` — send/receive STREAM FSMs, reassembly, flow control.
  - `QUICConnectionCore` — DPLPMTUD, transport-params codec, packet parse/serialize.
  - `QUICConnectionEngineCore` — `QUICConnectionEngine<C, T>`, the cored
    orchestrator that DRIVES the other six (the 7th, newest core). See its own
    CONTEXT.
- **Host adapters (Foundation).** `QUICCore` / `QUICCrypto` / `QUICConnection` /
  `QUICRecovery` / `QUICStream` / `QUICTransport` / `QUIC`. They hold the cores
  (under `Mutex` where mutable), bridge `Data`/`SymmetricKey`, and add the I/O
  orchestration. These remain the unchanged public API for callers.

## Contracts (the load-bearing rules)

- **The crypto seam is the only crypto path.** Every core is generic over
  `C: CryptoProvider`; no core imports a concrete cryptographic engine
  directly. The host adapters specialise every generic engine at
  `C = QUICCryptoProvider` (the unified `DefaultCryptoProvider`, except ECDSA is
  DER-encoded for the TLS path). Do not reach around the seam.
- **Cipher-suite dispatch is `SuiteProtector<C>`, a closed enum** over
  `PacketProtector<C, A>` (AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305). It
  replaced the old `any PacketOpener` / `any PacketSealer` existentials. Do not
  reintroduce `any` for cipher-suite polymorphism.
- **Cipher suite negotiated by TLS must propagate to packet protection.** Carry
  it through `KeysAvailableInfo.cipherSuite` / `QUICProtectionSuite` and select
  the protector via the key-derivation factory. Never hardcode AES on the
  key-installation path.

## Invariants (must hold; tests guard them)

- **Fail-closed peer authentication.** CertificateVerify proof-of-possession is
  always verified when the peer presents a certificate; a server cannot skip
  Certificate/CertificateVerify, and Finished is accepted only after
  authentication completes. There is no silent fallback to an unauthenticated
  channel (RFC 8446 §4.4.3 / RFC 9001).
- **ACK processing is DoS-bounded.** Loss detection never iterates an
  attacker-controlled range. It iterates the locally-known sent packets and tests
  membership against the ACK ranges, so cost is `O(sentPackets × ranges)`, not
  `O(Σ range_length)`. ACK ranges are also capped (256) and gap/length arithmetic
  is underflow-checked.
- **Loss recovery follows RFC 9002.** Packet-threshold (3) and time-threshold
  detection, PTO with exponential backoff, persistent-congestion detection.
- **Flow control is enforced and connection-fatal on violation** (RFC 9000 §4):
  connection- and stream-level limits; a peer exceeding an advertised limit is a
  FLOW_CONTROL_ERROR. Final-size immutability (§4.5) is reconciled against
  buffered out-of-order data.
- **1-RTT key update is RFC 9001 §6.** Usage-limit-driven initiation (per-suite
  AEAD confidentiality/integrity limits), cipher-suite-correct next-generation
  key derivation, key-phase-correct opener selection on receive. Known
  limitation: continuous multi-generation rotation is not yet live; only the
  first rotation occurs automatically.
- **Integer safety throughout.** Network-sourced `UInt64 → Int` conversions go
  through `SafeConversions`; amplification/byte tracking uses saturating
  arithmetic; `ConnectionID` is 0–20 bytes via a throwing initializer
  (RFC 9000 §17.2).
- **Anti-amplification (RFC 9000 §8.1).** A server sends at most 3× the bytes it
  received before address validation; a PATH_RESPONSE for an unvalidated path is
  charged against that budget and sent on the path the challenge arrived on
  (§8.2.1).
- **Transport-parameter ↔ Connection-ID cross-validation (RFC 9000 §7.3):**
  `initial_source_connection_id` / `original_destination_connection_id` /
  `retry_source_connection_id` checked against the CIDs observed during the
  handshake; a mismatch is TRANSPORT_PARAMETER_ERROR.

## Embedded constraints (do not regress)

- The cores must stay Embedded-clean: no Foundation, no `any` existentials, no
  `Mutex` / `ContinuousClock`, no direct crypto library. Typed throws only; closed
  enums instead of `any`. A cross-type `catch` must live in a NAMED function, not
  a closure literal (Embedded binds `any Error` inside a closure `catch`).
- `P2P_CORE_EMBEDDED=1` (a `Context.environment` toggle in `Package.swift`)
  enables the experimental `Embedded` feature + whole-module optimization for the
  cores. `Lifetimes` is enabled in BOTH modes (Span-returning members of the
  `P2PCoreBytes` dependency require `@_lifetime`).
- Time never enters a core via a clock: it is injected as a monotonic
  `nowNanos: UInt64`.

## Status: portable engine facade compiles as the `QUIC` product

The WASM and Embedded WASM compile covers the `QUIC` product, including its
cores and portable engine facade. A seam-based driver `QUICEngineConnection`
(`Sources/QUIC/`) holds `FacadeLock<QUICConnectionEngine>` over the
`DatagramTransport` (UDP) + `AsyncTimer` (clock+sleep) seams, inverts I/O, and runs
the clock-free timer loop — unit-tested end-to-end (`QUICEngineConnectionTests`).
It is ADDITIVE: `QUICEndpoint`/`ManagedConnection` keep their proven
`QUICConnectionHandler`/`PacketProcessor` spine, so the public Foundation/NIO API
+ remains intact and swift-libp2p still builds. Normal WASI and Embedded builds
exclude those host adapters and expose the `[UInt8]` / `SocketEndpoint` engine
surface from the same `QUIC` product. The host API uses an injected
`SwiftSSLQUICTLSProviderFactory`; testing mode without an injected provider
fails explicitly instead of selecting a built-in mock TLS implementation.

## Build

- Host: `xcodebuild build` / `xcodebuild test` with the pinned Swift 6.4
  development snapshot (Swift tools 6.2, platform floor v26).
- WASM: use the matching Swift 6.4 WASM SDK with
  `P2P_CORE_WASM=1 swift build --target QUIC --configuration release`.
- Embedded WASM: use the matching Swift 6.4 Embedded WASM SDK with
  `P2P_CORE_EMBEDDED=1 swift build --target QUIC --configuration release`.

## References

- RFC 9000 (QUIC Transport), RFC 9001 (QUIC-TLS), RFC 9002 (Loss Detection /
  Congestion Control), RFC 9218 (priorities), RFC 8446 (TLS 1.3).
