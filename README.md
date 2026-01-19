# swift-quic

A pure Swift implementation of the QUIC transport protocol (RFC 9000, 9001, 9002).

## Overview

swift-quic provides a modern, type-safe QUIC implementation designed for the swift-libp2p networking stack. It leverages Swift's concurrency features and follows protocol-oriented design principles.

## Features

- **RFC 9000/9001/9002 Compliant**: Full QUIC transport protocol implementation
- **TLS 1.3 Integration**: Native TLS 1.3 handshake with certificate validation
- **0-RTT Support**: Early data transmission with session resumption
- **Connection Migration**: PATH_CHALLENGE/RESPONSE with address validation
- **Type-Safe**: Leverages Swift's type system for compile-time safety
- **Modern Concurrency**: Built with async/await, Sendable types, and structured concurrency
- **Modular Design**: Clean separation between core types, crypto, and connection handling
- **High Performance**: Optimized for 1Gbps+ throughput with low-latency packet processing
- **Memory Safe**: Validated encoding/decoding with bounds checking and overflow protection
- **Graceful Shutdown**: Proper continuation management prevents hangs
- **Security Hardened**: Integer overflow protection, ACK range validation, race condition prevention

## Requirements

- Swift 6.0+
- macOS 15.0+ / iOS 18.0+ / tvOS 18.0+ / watchOS 11.0+ / visionOS 2.0+

## Installation

Add swift-quic to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-quic.git", branch: "main")
]
```

## Architecture

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

## Module Structure

### QUIC

High-level API for QUIC connections:

- **QUICEndpoint**: Server and client endpoint management
- **ManagedConnection**: High-level connection with async stream APIs
- **ManagedStream**: Stream wrapper implementing QUICStreamProtocol
- **ConnectionRouter**: DCID-based packet routing with reverse mapping
- **PacketProcessor**: Unified packet encryption/decryption

### QUICCore

Core types and packet processing:

- **Varint**: Variable-length integer encoding (RFC 9000 Section 16)
- **ConnectionID**: Connection identification with secure random generation
- **PacketHeader**: Long and Short header parsing with validation
- **Frame**: All 19 QUIC frame types
- **FrameCodec**: Frame encoding/decoding with varint frame type support
- **PacketCodec**: Packet encoding/decoding with encryption and Initial packet padding
- **CoalescedPackets**: Multiple packet handling

### QUICCrypto

Cryptographic operations:

- **InitialSecrets**: Initial key derivation (RFC 9001)
- **KeyMaterial**: Encryption key management
- **AEAD**: AES-128-GCM and ChaCha20-Poly1305 encryption
- **HeaderProtection**: AES-ECB header protection
- **KeyUpdate**: AEAD limit tracking and key rotation (RFC 9001 Section 6)
- **RetryIntegrityTag**: Retry packet integrity verification (RFC 9001 Section 5.8)
- **TLS13Handler**: Native TLS 1.3 handshake state machine
- **SessionTicketStore**: Server-side session ticket management
- **ClientSessionCache**: Client-side session resumption
- **ReplayProtection**: 0-RTT replay attack prevention

### QUICRecovery

Loss detection and congestion control (RFC 9002):

- **RTTEstimator**: Smoothed RTT calculation with min RTT tracking
- **AckManager**: Interval-based ACK frame generation with O(1) sequential packet tracking
- **LossDetector**: Packet/time threshold loss detection with single-pass processing
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

## Usage

### High-Level API (ManagedConnection)

```swift
import QUIC

// Server: Accept incoming connections
let endpoint = QUICEndpoint(role: .server)
try await endpoint.start(address: SocketAddress(ipAddress: "0.0.0.0", port: 4433))

for try await connection in endpoint.incomingConnections {
    Task {
        // Handle incoming streams
        for try await stream in connection.incomingStreams {
            let data = try await stream.read()
            try await stream.write(responseData)
            try await stream.closeWrite()
        }
    }
}

// Client: Connect to server
let client = QUICEndpoint(role: .client)
let connection = try await client.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4433))

// Open a stream
let stream = try await connection.openStream()
try await stream.write(requestData)
try await stream.closeWrite()
let response = try await stream.read()

// Graceful shutdown
await connection.shutdown()
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

// Parse a packet header
let (header, headerLength) = try PacketHeader.parse(from: packetData)

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

## Performance

Benchmarks measured on Apple Silicon (arm64-apple-macosx):

### Packet Processing

| Operation | Performance |
|-----------|-------------|
| Short header parsing | 6.3M ops/sec |
| Long header parsing | 228K ops/sec |
| DCID extraction (short) | 835K ops/sec |
| DCID extraction (long) | 923K ops/sec |
| ConnectionRouter lookup | 428K ops/sec |
| Packet type extraction | 7.8M ops/sec |

### Core Operations

| Operation | Performance |
|-----------|-------------|
| Varint encoding | 7.8M ops/sec |
| Varint decoding | 450K ops/sec |
| Varint fast path (1-byte) | 11.6M ops/sec |
| ConnectionID creation | 678K ops/sec |
| ConnectionID equality | 45.3M ops/sec |
| ConnectionID hash | 16.1M ops/sec |
| ConnectionID random | 809K ops/sec |
| CID Dictionary lookup | 10.7M ops/sec |

### Frame Operations

| Operation | Performance |
|-----------|-------------|
| PING frame encoding | 9.8M ops/sec |
| PING frame decoding | 22.0M ops/sec |
| ACK frame encoding | 610K ops/sec |
| ACK frame decoding | 2.0M ops/sec |
| STREAM frame encoding | 2.3M ops/sec |
| Frame roundtrip | 986K ops/sec |

### Crypto Operations

| Operation | Performance |
|-----------|-------------|
| Initial key derivation | 13.1K ops/sec |
| KeyMaterial derivation | 49.6K ops/sec |
| AES-GCM Sealer creation | 12.0M ops/sec |

### Packet Operations

| Operation | Performance |
|-----------|-------------|
| Packet number encoding | 4.8M ops/sec |
| Packet number decoding | 10.2M ops/sec |
| Coalesced packet building | 823K ops/sec |
| Coalesced packet parsing | 133K ops/sec |

### Recovery Performance

| Operation | Performance |
|-----------|-------------|
| Sequential packet recording | 11.0M ops/sec |
| ACK frame generation | 34.9K ops/sec |
| Packet send recording | 3.7M ops/sec |
| Loss detection | 5.5K ops/sec |
| Full ACK cycle | 503K pkts/sec |
| Realistic QUIC stream | 45K pkts/sec |

### Memory Efficiency

| Metric | Value |
|--------|-------|
| STREAM frame overhead (100B-10KB) | 4 bytes |
| Coalesced packet overhead | 0 bytes |
| 10K sequential packets storage | 1 range |
| AckManager max ranges | 256 |

Run benchmarks:

```bash
swift test --filter QUICBenchmarks
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
- **RFC 9000 Section 8.1**: Anti-Amplification Limit
  - Server-side 3x amplification limit before address validation
  - Overflow-safe byte tracking with saturating arithmetic
- **RFC 9000 Section 12.4**: Varint-encoded frame types (supports extended frame types)
- **RFC 9000 Section 14.1**: Initial packet minimum size (1200 bytes) with automatic padding
- **RFC 9000 Section 17**: Long and Short header formats with validation
- **RFC 9000 Section 19**: All 19 frame types with proper encoding/decoding
- **RFC 9001 Section 4**: 0-RTT early data with replay protection
- **RFC 9001 Section 5.2**: Initial keys with AES-128-GCM-SHA256
- **RFC 9001 Section 5.4**: Header protection with 4-byte packet number handling
- **RFC 9001 Section 5.8**: Retry packet integrity tag verification
- **RFC 9001 Section 6**: Key Update mechanism with AEAD limit tracking
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

### Security

- Integer overflow protection with saturating arithmetic
- ACK range underflow validation (prevents malformed ACK processing)
- ACK range count validation (prevents memory exhaustion attacks)
- PATH_CHALLENGE/PATH_RESPONSE 8-byte payload enforcement
- STREAM/DATAGRAM frame boundary validation
- Flow control violation detection (connection close on violation)
- RESET_STREAM final size validation against advertised limits
- DCID length validation (0-20 bytes per RFC 9000 Section 17.2)
- Double-start prevention in connection handshake
- Race condition prevention in shutdown paths
- Graceful shutdown prevents continuation leaks and resource exhaustion

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
  - [x] KeyUpdate for AEAD limit tracking
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

## License

MIT License

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting a pull request.
