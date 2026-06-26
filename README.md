# swift-quic

A pure Swift implementation of the QUIC transport protocol (RFC 9000, 9001, 9002), designed for the swift-libp2p networking stack. It is **Embedded-first**: the protocol logic lives in value-type, sans-IO core targets whose byte currency is `[UInt8]` / `Span`, with thin Foundation host adapters over them.

> **Release status.** The released `1.3.0` ships the prior host API. The Embedded-first cores documented here live on the unreleased `embedded` branch (M8 pending) and are not tagged — pin to the branch to use them. The host orchestrator (`QUICEndpoint` / `ManagedConnection` / `TimerManager`) is not yet rewired onto the cored `QUICConnectionEngine` (quic Slice B / M11 pending).

## Features

- **RFC 9000/9001/9002 Compliant**: Full QUIC transport protocol implementation
- **TLS 1.3 Integration**: Native TLS 1.3 handshake with certificate validation (via [swift-certificates](https://github.com/apple/swift-certificates))
- **Enforced Peer Authentication**: CertificateVerify signature is always verified; a server cannot skip Certificate/CertificateVerify, and Finished is accepted only after authentication completes (no unauthenticated/MITM channel)
- **0-RTT Support**: Early data transmission with session resumption
- **Connection Migration**: PATH_CHALLENGE/RESPONSE with address validation
- **Type-Safe**: Leverages Swift's type system for compile-time safety
- **Modern Concurrency**: Built with async/await, Sendable types, and structured concurrency
- **Modular Design**: Clean separation between core types, crypto, and connection handling
- **High Performance**: Optimized for 1Gbps+ throughput
  - Loss detection: 26K ops/sec
  - Multi-range ACK: 4.8K ops/sec
  - Full ACK cycle: 1.9M pkts/sec
- **Memory Safe**: Validated encoding/decoding with bounds checking and overflow protection
- **Graceful Shutdown**: Proper continuation management prevents hangs
- **Security Hardened**: Integer overflow protection, ACK range validation, race condition prevention, enforced peer authentication, and RFC-mandated frame/transport-parameter validations (see [Security](#security))

## Requirements

- Swift tools 6.2+
- macOS 26+ / iOS 26+ / tvOS 26+ / watchOS 26+ / visionOS 26+

## Installation

Add swift-quic to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-quic.git", from: "1.3.0")
]
```

The latest released tag is `1.3.0`, which ships the host API (Foundation-backed
`QUIC` / `QUICCore` / `QUICCrypto` ...). The Embedded-clean core targets described
under [Products](#products) — `QUICWire`, `QUICPacketProtectionCore`,
`QUICRecoveryCore`, `QUICStreamCore`, `QUICTLSCore`, `QUICConnectionCore`,
`QUICConnectionEngineCore` — are **unreleased**: they live on the `embedded`
branch and are not yet part of a tagged release. To use them, point at the branch:

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-quic.git", branch: "embedded")
]
```

### Dependencies

swift-quic uses the following libraries:

- [swift-crypto](https://github.com/apple/swift-crypto) (`3.12.3 ..< 5.0.0`) - Cryptographic operations
- [swift-certificates](https://github.com/apple/swift-certificates) (`1.17.0+`) - X.509 certificate handling
- [swift-asn1](https://github.com/apple/swift-asn1) (`1.5.0+`) - ASN.1 encoding/decoding
- [swift-log](https://github.com/apple/swift-log) (`1.9.0+`) - Logging
- [swift-docc-plugin](https://github.com/swiftlang/swift-docc-plugin) (`1.4.3+`) - Documentation
- swift-p2p-core - Embedded-clean byte primitives (`Bytes`/`ByteReader`/`ByteWriter`) + crypto seam
- swift-p2p-crypto - Unified `DefaultCryptoProvider` (host swift-crypto / Embedded BoringSSL)
- swift-nio-udp - UDP transport (local-path dependency on the `embedded` branch)

## Quick Start

### High-Level API (ManagedConnection)

```swift
import QUIC

// A TLS 1.3 provider must always be configured (no insecure default).
// Use .production / .development with your own provider, or .testing in unit tests.
let config = QUICConfiguration.production { MyTLSProvider() }

// Server: bind a socket, serve, and accept incoming connections
let serverSocket = NIOQUICSocket(configuration: .unicast(port: 4433))
let (server, _) = try await QUICEndpoint.serve(socket: serverSocket, configuration: config)

for await connection in server.incomingConnections {
    Task {
        // Handle incoming streams
        for await stream in connection.incomingStreams {
            let data = try await stream.read()
            try await stream.write(data)
            try await stream.closeWrite()
        }
    }
}

// Client: dial a server (returns once the handshake completes)
let client = QUICEndpoint(configuration: config)
let connection = try await client.dial(address: SocketAddress(ipAddress: "127.0.0.1", port: 4433))

// Open a stream
let stream = try await connection.openStream()
try await stream.write(requestData)
try await stream.closeWrite()
let response = try await stream.read()

// Graceful shutdown
await connection.close(error: nil)
try await client.shutdown()
```

### Frame Encoding/Decoding

```swift
import QUICCore

let codec = StandardFrameCodec()

// Encode frames
let frames: [Frame] = [
    .ping,
    .ack(AckFrame(largestAcknowledged: 100, ackDelay: 10, ackRanges: [AckRange(gap: 0, rangeLength: 5)])),
    .stream(StreamFrame(streamID: 4, offset: 0, data: payload, fin: false))
]
let encoded = try codec.encodeFrames(frames)

// Decode frames
let decoded = try codec.decodeFrames(from: encoded)
```

### Packet Header Parsing

```swift
import QUICCore

// Parse a (still header-protected) packet header
let (header, headerLength) = try ProtectedPacketHeader.parse(from: packetData, dcidLength: 8)

switch header {
case .long(let longHeader):
    print("Long header: \(longHeader.packetType)")
    // Retry packets include integrity tag
    if longHeader.packetType == .retry {
        print("Retry token: \(longHeader.token?.count ?? 0) bytes")
        print("Integrity tag: \(longHeader.retryIntegrityTag?.count ?? 0) bytes")
    }
case .short(let shortHeader):
    print("Short header")
}
```

### Coalesced Packets

```swift
import QUICCore

// Build coalesced packet
var builder = CoalescedPacketBuilder(maxDatagramSize: 1200)
_ = builder.addPacket(initialPacket)
_ = builder.addPacket(handshakePacket)
let datagram = builder.build()

// Parse coalesced packet
let packets = try CoalescedPacketParser.parse(datagram: datagram, dcidLength: 8)
```

### Initial Packet Encoding (with automatic padding)

```swift
import QUICCore

let encoder = PacketEncoder()

// Initial packets are automatically padded to 1200 bytes (RFC 9000 Section 14.1)
let encoded = try encoder.encodeLongHeaderPacket(
    frames: frames,
    header: initialHeader,
    packetNumber: 0,
    sealer: sealer
)
// encoded.count >= 1200
```

## Products

swift-quic is split into two tiers:

- **Embedded-clean cores** (dual-build: host + Embedded Swift) — value-type,
  caller-locked, sans-IO building blocks generic over the crypto seam. No
  Foundation, no `any` existentials, no `Mutex`/`ContinuousClock`, typed throws.
  Cipher-suite dispatch is a closed `SuiteProtector<C>` enum, not `any
  PacketOpener`/`any PacketSealer`.
- **Host adapters** (Foundation-backed) — hold the cores under a `Mutex`, bridge
  `Data`/`SymmetricKey`, and add the I/O orchestration. These remain the public
  high-level API and are unchanged for callers.

### Embedded-clean Cores

#### QUICWire (Tier-3 wire codec)

Embedded-clean varint + frame + packet-header codec over `Bytes`/`[UInt8]`:

- **Varint**: Variable-length integer encoding (RFC 9000 Section 16)
- **ConnectionID**: Connection identification with secure random generation
- **PacketHeader**: Long and Short header parsing with validation
- **Version**: QUIC version constants, initial salt, retry-integrity key/nonce
- **Frame** / **FrameCodec** (`StandardFrameCodec`): all 19 QUIC frame types
- **ProtocolLimits**: RFC-compliant protocol limit constants
- **SafeConversions**: Overflow-checked integer conversions

#### QUICPacketProtectionCore

Embedded-clean packet protection generic over the crypto provider:

- **PacketProtector<C, A>**: AEAD payload protection + header protection over the `CryptoProvider` / `HeaderProtectionProvider` seam
- **SuiteProtector<C>**: closed cipher-suite enum (AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305) that replaces the `any PacketOpener`/`any PacketSealer` existentials
- **QUICKeyDerivation**: RFC 9001 §5.1 key material derivation

#### QUICRecoveryCore

Value-type loss detection + congestion control with time injected as a monotonic `UInt64` nanosecond parameter:

- **LossDetectorCore**: sorted-array packet/time threshold loss detection
- **RTTEstimatorCore**: RTT smoothing and min-RTT tracking
- **CubicCore** (RFC 9438) / **NewRenoCore** (RFC 9002 §7): congestion controllers
- **PacerCore**: token-bucket pacing (RFC 9002 §7.7)
- **AntiAmplificationCore**: server 3x amplification limit

#### QUICStreamCore

Value-type STREAM state machines over `[UInt8]` payloads (RFC 9000 §2-4):

- **SendStreamCore** / **ReceiveStreamCore**: send/receive FSMs
- **StreamReassemblyBuffer**: out-of-order reassembly
- **FlowControllerCore**: connection + stream-level flow control

#### QUICTLSCore

TLS 1.3 (RFC 8446) handshake + key schedule generic over `C: CryptoProvider`:

- **TLSKeyScheduleCore**: early/handshake/master secrets, HKDF-Expand-Label, traffic secrets, finished/verify-data (RFC 8446 §7.1)
- **TLSTranscriptHashCore**: incremental transcript hash
- **QUICClientHandshake** / **QUICServerHandshake** / **QUICClientAuthMachine**: handshake FSMs
- Handshake message + extension wire codecs (ClientHello, ServerHello, Certificate, ...)

#### QUICConnectionCore

Pure value-type connection state machines that are neither codec nor crypto:

- **PathMTUSearchCore**: DPLPMTUD search (RFC 8899 / RFC 9000 §14)
- **TransportParameterCodecCore** + **IPAddressCodec**: transport-params codec (RFC 9000 §18) with a Foundation-free IPv4/IPv6 parser
- **PacketParsingCore**: packet parse/serialize core driving `SuiteProtector<C>` (RFC 9000 §12/§17, RFC 9001 §5)
- **ConnectionStateCore** / **IdleTimeoutCore** / **PathValidationCore**: connection lifecycle state machines

#### QUICConnectionEngineCore

The cored connection orchestrator — `QUICConnectionEngine<C, T>`, a value-type,
caller-locked, sans-IO, clock-free engine that **drives** the other six cores
(packet-number spaces, recovery + CC + pacing, ACK generation, stream multiplex,
flow control, idle, path validation). Timers are clock-free: time is injected as
`nowNanos: UInt64`, and `deadlines(nowNanos:)` / `handleTimeout(nowNanos:)` mirror
the DTLS engine pattern. I/O is inverted to the facade, which owns the
`DatagramTransport` + `AsyncTimer`. Crypto/cert are injected via typed-throws
closures; X.509 stays out of the engine. **Status:** this is the substrate for the
upcoming facade rewire — the host orchestrator (`QUICEndpoint` / `ManagedConnection`
/ `TimerManager`) is **not yet rewired onto it** (quic Slice B / M11 pending).

### Host Adapters

### QUIC

High-level API for QUIC connections (host-only; not yet ported to a cored engine):

- **QUICEndpoint**: Server and client endpoint management
- **ManagedConnection**: High-level connection with async stream APIs
- **ManagedStream**: Stream wrapper implementing QUICStreamProtocol
- **ConnectionRouter**: DCID-based packet routing with reverse mapping
- **PacketProcessor**: Unified packet encryption/decryption (over `SuiteProtector<C>`)
- **TimerManager**: Loss-detection / PTO timer scheduling

### QUICCore

Foundation adapter over `QUICWire` + `QUICConnectionCore`. Restores the historical
`Data`-based views over the Embedded-clean wire codec:

- **Varint**: Variable-length integer encoding (RFC 9000 Section 16)
- **ConnectionID**: Connection identification with secure random generation
- **PacketHeader**: Long and Short header parsing with validation
- **Frame**: All 19 QUIC frame types
- **FrameCodec**: Frame encoding/decoding with varint frame type support
- **PacketCodec**: Packet encoding/decoding with encryption and Initial packet padding
- **CoalescedPackets**: Multiple packet handling

> The wire codec primitives (`Varint`, `ConnectionID`, `PacketHeader`, `Version`,
> `Frame`/`FrameCodec`, `ProtocolLimits`, `SafeConversions`) now live in
> `QUICWire`; `QUICCore` re-exports Foundation-friendly adapters over them.

### QUICCrypto

Cryptographic operations (Foundation adapter over `QUICTLSCore` +
`QUICPacketProtectionCore`, specialised at `C = QUICCryptoProvider`, the unified
`DefaultCryptoProvider`):

- **InitialSecrets**: Initial key derivation (RFC 9001)
- **KeyMaterial**: Encryption key management
- **AEAD**: AES-128-GCM and ChaCha20-Poly1305 encryption (over `PacketProtector<C,A>`)
- **HeaderProtection**: header protection routed through the `HeaderProtectionProvider` seam (`DefaultCryptoProvider`: host swift-crypto / Embedded BoringSSL)
- **KeyUpdate**: AEAD limit tracking and key rotation (RFC 9001 Section 6)
- **RetryIntegrityTag**: Retry packet integrity verification (RFC 9001 Section 5.8)
- **TLS13Handler**: Native TLS 1.3 handshake state machine
- **SessionTicketStore**: Server-side session ticket management
- **ClientSessionCache**: Client-side session resumption
- **ReplayProtection**: 0-RTT replay attack prevention
- **X509Certificate**: X.509 certificate handling (via [swift-certificates](https://github.com/apple/swift-certificates))
- **X509Validator**: Certificate chain validation with EKU/SAN/NameConstraints

### QUICRecovery

Loss detection and congestion control (RFC 9002):

- **RTTEstimator**: Smoothed RTT calculation with min RTT tracking
- **AckManager**: Interval-based ACK frame generation with O(1) sequential packet tracking
- **LossDetector**: Optimized packet/time threshold loss detection
  - Sorted array storage for cache-efficient iteration
  - Binary search for O(log n) range queries
  - Bounded iteration (only processes relevant packets)
- **PacketNumberSpaceManager**: Multi-level packet number space coordination
- **SentPacket**: Sent packet metadata for loss tracking
- **CongestionController**: Congestion control protocol with pacing support
- **NewRenoCongestionController**: NewReno implementation with slow start, congestion avoidance, and recovery
- **AntiAmplificationLimiter**: Server-side 3x amplification limit (RFC 9000 Section 8.1)

### QUICConnection

Connection state management:

- **ConnectionState**: State machine for QUIC connections
- **QUICConnectionHandler**: Main connection orchestrator
- **CryptoStreamManager**: CRYPTO frame reassembly
- **PathValidationManager**: PATH_CHALLENGE/RESPONSE handling
- **StatelessResetManager**: Stateless reset token generation and validation
- **IdleTimeoutManager**: Connection idle timeout tracking

### QUICTransport

Transport-level features:

- **ECN**: Explicit Congestion Notification support
- **Pacing**: Token bucket pacing for burst prevention
- **UDPSocket**: UDP datagram transmission

### QUICStream

Stream management and flow control (RFC 9000 Section 2-4):

- **DataStream**: Individual stream state machine with send/receive buffers
- **StreamManager**: Stream multiplexing, creation, and lifecycle management
- **FlowController**: Connection and stream-level flow control
- **DataBuffer**: Out-of-order data reassembly with FIN tracking
- **StreamState**: Send/receive state machines per RFC 9000

## Architecture

The public surface is the host `QUIC` facade; below it sit the Embedded-clean
cores (see [Products](#products)). The host orchestration layering:

```
┌─────────────────────────────────────────────────────────────┐
│  QUICEndpoint (Server/Client Entry Point)                   │
├─────────────────────────────────────────────────────────────┤
│  ManagedConnection (High-Level Connection API)              │
│  - AsyncStream<QUICStreamProtocol> for incoming streams     │
│  - Graceful shutdown with continuation cleanup              │
├─────────────────────────────────────────────────────────────┤
│  ConnectionRouter (DCID-based Packet Routing)               │
├─────────────────────────────────────────────────────────────┤
│  QUICConnectionHandler (Connection State Machine)           │
├─────────────────────────────────────────────────────────────┤
│  PacketProcessor (Encryption/Decryption Integration)        │
├─────────────────────────────────────────────────────────────┤
│  QUICStream (Stream Multiplexing, Flow Control)             │
├─────────────────────────────────────────────────────────────┤
│  Packet Codec (Encoding/Decoding with Encryption)           │
├─────────────────────────────────────────────────────────────┤
│  Frame Codec (All 19 QUIC Frame Types)                      │
├─────────────────────────────────────────────────────────────┤
│  Coalesced Packets (Multiple packets per UDP datagram)      │
├─────────────────────────────────────────────────────────────┤
│  Crypto (AEAD, Header Protection, Key Derivation)           │
├─────────────────────────────────────────────────────────────┤
│  Core Types (Varint, ConnectionID, Version, Headers)        │
└─────────────────────────────────────────────────────────────┘
```

The cored `QUICConnectionEngine<C, T>` (in `QUICConnectionEngineCore`) is the
value-type, sans-IO substrate that will replace the per-connection orchestration
the host layers above perform under `Mutex`; the facade rewire onto it is the
pending quic Slice B (M11) work.

## Security

- Enforced peer authentication: CertificateVerify signature is always verified; a server cannot skip Certificate/CertificateVerify, and Finished is accepted only after authentication (no silent fallback to an unauthenticated channel)
- Integer overflow protection with saturating arithmetic
- ACK range underflow validation (prevents malformed ACK processing)
- ACK range count validation (prevents memory exhaustion attacks)
- ACK processing is DoS-bounded: loss detection iterates the locally-known sent packets and tests membership against the ACK ranges (`O(sentPackets × ranges)`), never iterating an attacker-controlled range
- PATH_CHALLENGE/PATH_RESPONSE 8-byte payload enforcement
- Path-bound, amplification-budgeted PATH_RESPONSE (RFC 9000 Section 8.2.1: a response for an unvalidated path is charged against the 3x anti-amplification budget and sent on the path the challenge arrived on)
- STREAM/DATAGRAM frame boundary validation
- STREAM/CRYPTO final-offset bound: `offset + length` must not exceed 2^62-1
- Flow control violation detection (connection close on violation)
- RESET_STREAM final size validation against advertised limits and reconciliation with previously received/buffered data (final-size immutability)
- NEW_CONNECTION_ID `retire_prior_to` bound (`retire_prior_to <= sequence_number`; anti-DoS)
- `active_connection_id_limit` clamped to a practical maximum to bound state
- Transport-parameter <-> Connection-ID cross-validation (RFC 9000 Section 7.3): `initial_source_connection_id`, `original_destination_connection_id`, and `retry_source_connection_id` are checked against the connection IDs observed during the handshake (mismatch is a TRANSPORT_PARAMETER_ERROR)
- DCID length validation (0-20 bytes per RFC 9000 Section 17.2)
- Double-start prevention in connection handshake
- Race condition prevention in shutdown paths
- Graceful shutdown prevents continuation leaks and resource exhaustion

## RFC Compliance

### Implemented

- **RFC 9000 Section 2**: Stream types (bidirectional, unidirectional) with proper ID assignment
- **RFC 9000 Section 3**: Stream state machines (send/receive states)
- **RFC 9000 Section 3.5**: STOP_SENDING triggers RESET_STREAM generation
- **RFC 9000 Section 4**: Flow control (connection and stream level)
- **RFC 9000 Section 4.5**: Stream Final Size validation
  - Final size immutability enforcement
  - RESET_STREAM final size vs flow control limit validation
  - Out-of-order FIN validation against buffered data
- **RFC 9000 Section 7.3**: Transport-parameter <-> Connection-ID cross-validation
  - `initial_source_connection_id`, `original_destination_connection_id`, and `retry_source_connection_id` checked against connection IDs observed during the handshake (mismatch is TRANSPORT_PARAMETER_ERROR)
- **RFC 9000 Section 8.1**: Anti-Amplification Limit
  - Server-side 3x amplification limit before address validation
  - Overflow-safe byte tracking with saturating arithmetic
- **RFC 9000 Section 8.2.1**: Path-bound, amplification-budgeted PATH_RESPONSE
  - A PATH_RESPONSE for an unvalidated path is charged against the anti-amplification budget and sent on the path the challenge arrived on
- **RFC 9000 Section 12.4**: Varint-encoded frame types (supports extended frame types)
- **RFC 9000 Section 14.1**: Initial packet minimum size (1200 bytes) with automatic padding
- **RFC 9000 Section 17**: Long and Short header formats with validation
- **RFC 9000 Section 19**: All 19 frame types with proper encoding/decoding
- **RFC 9001 Section 4**: 0-RTT early data with replay protection
- **RFC 9001 Section 5.2**: Initial keys with AES-128-GCM-SHA256
- **RFC 9001 Section 5.4**: Header protection with 4-byte packet number handling
- **RFC 9001 Section 5.8**: Retry packet integrity tag verification
- **RFC 9001 Section 6**: 1-RTT Key Update wired into the live connection
  - Usage-limit-driven initiation (AEAD confidentiality/integrity limits per cipher suite)
  - Cipher-suite-correct key derivation and key-phase opener selection on receive
  - Known limitation: continuous multi-generation rotation (ACK-driven re-enable of subsequent updates) is not yet live; only the first rotation occurs automatically
- **RFC 9218**: Extensible priority scheme (urgency 0-7, incremental flag)
  - Priority-based stream scheduling
  - Fair queuing within same priority level (round-robin)
  - Mutable stream priorities
- **RFC 9002 Section 6**: Loss Detection
  - Packet and time threshold based detection
  - PTO (Probe Timeout) calculation
- **RFC 9002 Section 7**: Congestion Control
  - NewReno congestion controller with slow start, congestion avoidance, recovery
  - Pacing support for burst prevention
  - Persistent congestion detection
  - ECN congestion event handling
- **RFC 9221**: Unreliable DATAGRAM extension (frame types 0x30 / 0x31, with and without an explicit length field)
- **RFC 9369**: QUIC Version 2 (version `0x6b3343cf`, with the v2-specific Initial salt and Retry integrity key/nonce)

The cryptographic constants are verified against the specifications: the v1/v2
Initial salts, the HKDF-Expand-Label `"tls13 "` prefix and QUIC labels
(`"client in"` / `"server in"` / `"quic key"` / `"quic iv"` / `"quic hp"` /
`"quic ku"`), the AES-128-GCM key/IV/tag sizes (16/12/16 bytes), the header-protection
sample offset (`pn_offset + 4`, 16 bytes) and first-byte masks (0x0F long / 0x1F
short), the nonce construction (IV XOR left-padded PN), and the v1/v2 Retry
integrity key+nonce.

### Compliance summary

| RFC | Title | Status |
|-----|-------|--------|
| RFC 9000 | QUIC: A UDP-Based Multiplexed and Secure Transport | Compliant |
| RFC 9001 | Using TLS to Secure QUIC | Compliant |
| RFC 9002 | QUIC Loss Detection and Congestion Control | Compliant |
| RFC 9221 | Unreliable DATAGRAM Extension | Compliant |
| RFC 9369 | QUIC Version 2 | Compliant |

## Performance

Benchmarks measured on Apple Silicon (arm64-apple-macosx):

### Packet Processing

| Operation | Performance |
|-----------|-------------|
| Short header parsing | 4.7M ops/sec |
| Long header parsing | 1.4M ops/sec |
| DCID extraction (short) | 6.5M ops/sec |
| DCID extraction (long) | 21.2M ops/sec |
| ConnectionRouter lookup | 3.4M ops/sec |
| Packet type extraction | 5.6M ops/sec |

### Core Operations

| Operation | Performance |
|-----------|-------------|
| Varint encoding | 3.4M ops/sec |
| Varint decoding | 5.8M ops/sec |
| Varint fast path (1-byte) | 12.5M ops/sec |
| ConnectionID creation | 1.4M ops/sec |
| ConnectionID equality | 42.3M ops/sec |
| ConnectionID hash | 16.6M ops/sec |
| ConnectionID random | 3.1M ops/sec |
| CID Dictionary lookup | 10.5M ops/sec |

### Frame Operations

| Operation | Performance |
|-----------|-------------|
| PING frame encoding | 24.5M ops/sec |
| PING frame decoding | 22.2M ops/sec |
| ACK frame encoding | 1.1M ops/sec |
| ACK frame decoding | 1.9M ops/sec |
| STREAM frame encoding | 2.1M ops/sec |
| Frame roundtrip | 1.0M ops/sec |

### Crypto Operations

| Operation | Performance |
|-----------|-------------|
| Initial key derivation | 23K ops/sec |
| KeyMaterial derivation | 95.5K ops/sec |
| AES-GCM Sealer creation | 4.1M ops/sec |

### Packet Operations

| Operation | Performance |
|-----------|-------------|
| Packet number encoding | 4.8M ops/sec |
| Packet number decoding | 5.5M ops/sec |
| Coalesced packet building | 940K ops/sec |
| Coalesced packet parsing | 572K ops/sec |

### Recovery Performance

| Operation | Performance |
|-----------|-------------|
| Sequential packet recording | 9.7M ops/sec |
| ACK frame generation | 139K ops/sec |
| Packet send recording | 3.5M ops/sec |
| **Loss detection** | **26.0K ops/sec** |
| **Multi-range ACK (25 ranges)** | **4.8K ops/sec** |
| Full ACK cycle | 1.9M pkts/sec |
| Realistic QUIC stream | 219K pkts/sec |

### Memory Efficiency

| Metric | Value |
|--------|-------|
| STREAM frame overhead (100B-10KB) | 4 bytes |
| Coalesced packet overhead | 0 bytes |
| 10K sequential packets storage | 1 range |
| AckManager max ranges | 256 |

Run benchmarks:

```bash
SWIFT_QUIC_ENABLE_BENCHMARKS=1 swift test --filter QUICBenchmarks
swift test --filter RecoveryBenchmarkTests
```

## Testing

Run all tests:

```bash
swift test
```

### Interoperability Testing

Verified interoperability with external QUIC implementations:

| Implementation | Language | Tests |
|----------------|----------|-------|
| Quinn | Rust | Basic handshake, Bidirectional stream, Version negotiation, 0-RTT, Path validation, Retry handling |
| ngtcp2 | C | Basic handshake, Version negotiation, Stream multiplexing |

Run interop tests (requires Docker):

```bash
cd docker && docker compose up -d
swift test --filter "QuinnInteropTests|Ngtcp2InteropTests"
```

### Unit Tests

Coverage includes:
- Frame encoding/decoding for all 19 frame types
- Packet encoding/decoding with header protection
- Coalesced packet building and parsing
- Varint encoding/decoding
- ConnectionID operations
- Header validation
- Loss detection and recovery (AckManager, LossDetector)
- Stream management (DataStream, StreamManager, FlowController)
- Flow control (connection and stream level)
- Out-of-order data reassembly (DataBuffer)
- Priority scheduling (StreamPriority, StreamScheduler)
- RFC 9000 Section 4.5 compliance (Stream Final Size)
- RFC 9001 test vectors (Initial secrets, key derivation)
- TLS 1.3 handshake flow (client/server, HelloRetryRequest)
- 0-RTT early data handling
- Key Update state transitions and AEAD limits
- Version Negotiation and Retry packet processing
- Anti-amplification limit enforcement
- ManagedConnection shutdown safety (continuation management)
- AsyncStream lifecycle and graceful termination
- Safe integer conversion (overflow/underflow protection)

Run specific test suites:

```bash
swift test --filter QUICCoreTests      # Core types
swift test --filter QUICCryptoTests    # Crypto operations
swift test --filter QUICRecoveryTests  # Loss detection
swift test --filter QUICStreamTests    # Stream management
swift test --filter QUICTests          # Integration tests
swift test --filter QUICBenchmarks     # Benchmarks
```

## Roadmap

- [x] Phase 1: Packet Processing Pipeline
  - [x] Frame Codec (all 19 frame types)
  - [x] Packet Codec (Long/Short headers with encryption)
  - [x] Coalesced Packets
  - [x] Initial packet padding (1200 bytes minimum)
  - [x] Retry packet integrity tag parsing
- [x] Phase 2: Connection Handler (RFC 9002)
  - [x] QUICConnectionHandler orchestrator
  - [x] AckManager with interval-based tracking
  - [x] LossDetector with packet/time threshold
  - [x] RTTEstimator with smoothed RTT
  - [x] PacketNumberSpaceManager
- [x] Phase 3: TLS 1.3 Integration (RFC 9001)
  - [x] TLS13Provider protocol
  - [x] MockTLSProvider for testing
  - [x] CryptoStreamManager for CRYPTO frame handling
  - [x] TransportParameters encoding/decoding
  - [x] KeySchedule with key update support
  - [x] KeyPhaseManager for 1-RTT key rotation
- [x] Phase 4: Stream Management (RFC 9000 Section 2-4)
  - [x] DataStream with send/receive state machines
  - [x] StreamManager for multiplexing and lifecycle
  - [x] FlowController (connection and stream level)
  - [x] DataBuffer for out-of-order reassembly
  - [x] STOP_SENDING/RESET_STREAM handling
  - [x] Priority scheduling (RFC 9218)
- [x] Phase 5: Version Negotiation & Retry
  - [x] VersionNegotiator for VN packet handling
  - [x] RetryIntegrityTag verification (RFC 9001 Section 5.8)
  - [x] AntiAmplificationLimiter (RFC 9000 Section 8.1)
- [x] Phase 6: Connection Migration
  - [x] PathValidationManager (PATH_CHALLENGE/RESPONSE)
  - [x] StatelessResetManager
  - [x] IdleTimeoutManager
- [x] Phase 7: 0-RTT & Session Resumption
  - [x] ClientSessionCache for session tickets
  - [x] SessionTicketStore for server-side
  - [x] ReplayProtection for 0-RTT
  - [x] startWith0RTT() API
- [x] Phase 8: Quality Improvements
  - [x] ECN support for congestion signaling
  - [x] Pacing for send rate control
  - [x] 1-RTT Key Update wired into the live connection (usage-limit-driven, cipher-suite-correct)
    - Known limitation: continuous multi-generation rotation (ACK-driven re-enable) is not yet live; only the first rotation is automatic
  - [x] ChaCha20-Poly1305 support
- [x] Phase 9: Security Hardening
  - [x] Integer overflow protection (saturating arithmetic)
  - [x] ACK range underflow validation
  - [x] Race condition prevention in shutdown
  - [x] Double-start vulnerability fix
- [x] Phase 10: Interoperability Testing
  - [x] Quinn (Rust) interop tests
  - [x] ngtcp2 (C) interop tests
  - [x] Docker-based test environment

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) - QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) - Using TLS to Secure QUIC
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) - QUIC Loss Detection and Congestion Control
- [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218.html) - Extensible Prioritization Scheme for HTTP
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) - An Unreliable Datagram Extension to QUIC
- [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html) - QUIC Version 2
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) - The Transport Layer Security (TLS) Protocol Version 1.3

## License

MIT License

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting a pull request.
