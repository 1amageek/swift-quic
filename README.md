# swift-quic

A pure Swift implementation of the QUIC transport protocol (RFC 9000, 9001, 9002).

## Overview

swift-quic provides a modern, type-safe QUIC implementation designed for the swift-libp2p networking stack. It leverages Swift's concurrency features and follows protocol-oriented design principles.

## Features

- **RFC 9000/9001/9002 Compliant**: Core QUIC transport protocol implementation
- **Type-Safe**: Leverages Swift's type system for compile-time safety
- **Modern Concurrency**: Built with async/await and Sendable types
- **Modular Design**: Clean separation between core types, crypto, and connection handling
- **High Performance**: Optimized varint decoding, inlined hot paths
- **Memory Safe**: Validated encoding/decoding with bounds checking

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
│  QUICConnection (Connection Handler)                        │
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
- **AEAD**: AES-128-GCM encryption
- **HeaderProtection**: AES-ECB header protection

### QUICRecovery

Loss detection and congestion control (RFC 9002):

- **RTTEstimator**: Smoothed RTT calculation with min RTT tracking
- **AckManager**: Interval-based ACK frame generation with O(1) sequential packet tracking
- **LossDetector**: Packet/time threshold loss detection with single-pass processing
- **PacketNumberSpaceManager**: Multi-level packet number space coordination
- **SentPacket**: Sent packet metadata for loss tracking

### QUICConnection

Connection state management:

- **ConnectionState**: State machine for QUIC connections
- **QUICConnectionHandler**: Main connection orchestrator
- **CryptoStreamManager**: CRYPTO frame reassembly

### QUICStream

Stream management and flow control (RFC 9000 Section 2-4):

- **DataStream**: Individual stream state machine with send/receive buffers
- **StreamManager**: Stream multiplexing, creation, and lifecycle management
- **FlowController**: Connection and stream-level flow control
- **DataBuffer**: Out-of-order data reassembly with FIN tracking
- **StreamState**: Send/receive state machines per RFC 9000

## Usage

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

### Core Operations

| Operation | Performance |
|-----------|-------------|
| Varint encoding | 3.3M ops/sec |
| Varint decoding | 2.3M ops/sec |
| ConnectionID creation | 1.4M ops/sec |
| ConnectionID equality | 49M ops/sec |

### Frame Operations

| Operation | Performance |
|-----------|-------------|
| PING frame encoding | 9.4M ops/sec |
| PING frame decoding | 21.8M ops/sec |
| ACK frame encoding | 1.3M ops/sec |
| ACK frame decoding | 1.6M ops/sec |
| STREAM frame encoding | 2.4M ops/sec |
| STREAM frame decoding | 5.0M ops/sec |
| CRYPTO frame encoding | 2.6M ops/sec |
| Multiple frames encoding | 200k ops/sec |
| Frame roundtrip | 846k ops/sec |

### Packet Operations

| Operation | Performance |
|-----------|-------------|
| Long header parsing | 834k ops/sec |
| Short header parsing | 5.7M ops/sec |
| Packet number encoding | 5.2M ops/sec |
| Packet number decoding | 8.2M ops/sec |
| Coalesced packet building | 751k ops/sec |
| Coalesced packet parsing | 324k ops/sec |
| Packet type sorting | 524k ops/sec |

### Loss Detection & Recovery (QUICRecovery)

| Operation | Performance |
|-----------|-------------|
| Sequential packet recording | 6.5M ops/sec |
| Packet recording with gaps | 1.2M ops/sec |
| ACK frame generation | 67k ops/sec |
| Packet send recording | 4.7M ops/sec |
| ACK processing (100 packets) | 12k ops/sec |
| Loss detection | 14k ops/sec |
| Multi-range ACK (25 ranges) | 4k ops/sec |
| Full ACK cycle (50 packets) | 10k packets/sec |

### Memory Efficiency

| Metric | Value |
|--------|-------|
| STREAM frame overhead (100B-10KB) | 4 bytes |
| Coalesced packet overhead | 0 bytes |
| 10K sequential packets storage | 1 range |
| AckManager max ranges | 256 |

Run benchmarks:

```bash
swift test --filter Benchmark
```

## Testing

Run all tests:

```bash
swift test
```

290 tests covering:
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
- RFC 9000 Section 4.5 compliance (Stream Final Size)
- Performance benchmarks

Run specific test suites:

```bash
swift test --filter FrameCodecTests
swift test --filter PacketCodecTests
swift test --filter CoalescedPacketsTests
swift test --filter QUICStreamTests
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
- **RFC 9000 Section 12.4**: Varint-encoded frame types (supports extended frame types)
- **RFC 9000 Section 14.1**: Initial packet minimum size (1200 bytes) with automatic padding
- **RFC 9000 Section 17**: Long and Short header formats with validation
- **RFC 9000 Section 19**: All 19 frame types with proper encoding/decoding
- **RFC 9001 Section 5.4**: Header protection with 4-byte packet number handling
- **RFC 9001 Section 5.8**: Retry packet integrity tag parsing

### Security

- ACK range count validation (prevents memory exhaustion attacks)
- PATH_CHALLENGE/PATH_RESPONSE 8-byte payload enforcement
- STREAM/DATAGRAM frame boundary validation
- Flow control violation detection (connection close on violation)
- RESET_STREAM final size validation against advertised limits

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
  - [ ] Priority scheduling
- [ ] Phase 5: Full Integration
  - [ ] E2E handshake with real TLS
  - [ ] Interoperability testing (quiche, quinn)

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) - QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) - Using TLS to Secure QUIC
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) - QUIC Loss Detection and Congestion Control

## License

MIT License

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting a pull request.
