# swift-quic Design Document

> **Project**: swift-quic - Pure Swift implementation of QUIC (RFC 9000)
> **Goal**: Provide a modern, async/await-based QUIC implementation for libp2p

## Overview

This is a clean-room implementation of QUIC protocol in Swift, designed primarily for libp2p integration but usable as a standalone QUIC library.

## Design Principles

Following swift-libp2p conventions:
- **async/await everywhere** - No EventLoopFuture
- **Value types first** - struct > class for data
- **Protocol-oriented** - Define protocols first, implementations separate
- **Sendable compliance** - All public types are Sendable
- **Mutex for state** - Use `Synchronization.Mutex<T>` for mutable state

## Code Review

**実装完了後は必ず以下のフローでレビューを実施すること。**

### フロー

1. **Codex CLIでレビュー実行**
2. **レビュー結果を考察** - 指摘の本質を理解する
3. **根本対応を検討** - 付け焼き刃な修正ではなく、問題の根本原因を解決する設計
4. **修正実施** - テストを追加し、全テストがパスすることを確認

### コマンド

```bash
# 全ソースをレビュー
codex exec --skip-git-repo-check -C "Review the Swift files in Sources/. Focus on memory safety, RFC 9000/9001/9002 compliance, bugs, security, and performance."

# 特定モジュールをレビュー
codex exec --skip-git-repo-check -C "Review Sources/QUICCore/Packet/ for RFC compliance."
```

レビュー結果はseverity（critical/warning/info）で分類される。criticalは即座に修正が必要。

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Application Layer                                          │
│  (QUICConnection, QUICStream)                               │
├─────────────────────────────────────────────────────────────┤
│  Stream Management                                          │
│  (Multiplexing, Flow Control per stream)                    │
├─────────────────────────────────────────────────────────────┤
│  Connection Layer                                           │
│  (Connection State Machine, Connection ID Management)       │
├─────────────────────────────────────────────────────────────┤
│  Loss Detection & Congestion Control                        │
│  (ACK Processing, Retransmission, CUBIC/NewReno)           │
├─────────────────────────────────────────────────────────────┤
│  Packet Layer                                               │
│  (Packet Number Encoding, Header Protection)                │
├─────────────────────────────────────────────────────────────┤
│  Frame Layer                                                │
│  (Frame Encoding/Decoding)                                  │
├─────────────────────────────────────────────────────────────┤
│  Crypto Layer (TLS 1.3)                                     │
│  (Handshake, Key Derivation, AEAD)                         │
├─────────────────────────────────────────────────────────────┤
│  UDP Transport (swift-nio-udp)                              │
└─────────────────────────────────────────────────────────────┘
```

## Module Structure

```
swift-quic/
├── Sources/
│   ├── QUIC/                    # Main public API
│   │   ├── QUICClient.swift     # Client-side connection establishment
│   │   ├── QUICListener.swift   # Server-side listener
│   │   ├── QUICConnection.swift # Multiplexed connection
│   │   ├── QUICStream.swift     # Individual stream
│   │   └── QUICConfiguration.swift
│   │
│   ├── QUICCore/                # Core types (no I/O dependencies)
│   │   ├── Packet/
│   │   │   ├── PacketHeader.swift      # Long/Short header
│   │   │   ├── PacketNumber.swift      # Packet number encoding
│   │   │   ├── ConnectionID.swift
│   │   │   └── Version.swift
│   │   ├── Frame/
│   │   │   ├── Frame.swift             # Frame enum
│   │   │   ├── StreamFrame.swift
│   │   │   ├── AckFrame.swift
│   │   │   ├── CryptoFrame.swift
│   │   │   └── ...
│   │   ├── Varint.swift                # QUIC variable-length integer
│   │   └── Error.swift
│   │
│   ├── QUICCrypto/              # TLS 1.3 integration
│   │   ├── TLS13.swift          # TLS 1.3 state machine
│   │   ├── KeySchedule.swift    # HKDF key derivation
│   │   ├── AEAD.swift           # AES-GCM / ChaCha20-Poly1305
│   │   ├── HeaderProtection.swift
│   │   └── CryptoState.swift
│   │
│   ├── QUICConnection/          # Connection management
│   │   ├── ConnectionState.swift
│   │   ├── ConnectionManager.swift
│   │   ├── PathManager.swift
│   │   └── IdleTimeout.swift
│   │
│   ├── QUICStream/              # Stream management (RFC 9000 Section 2-4)
│   │   ├── DataStream.swift       # Individual stream with send/receive state machines
│   │   ├── StreamManager.swift    # Stream multiplexing, creation, lifecycle
│   │   ├── FlowController.swift   # Connection & stream-level flow control
│   │   ├── DataBuffer.swift       # Out-of-order data reassembly
│   │   └── StreamState.swift      # Send/receive state enums
│   │
│   ├── QUICRecovery/            # Loss detection & congestion (RFC 9002)
│   │   ├── LossDetector.swift        # Packet loss detection with PTO support
│   │   ├── AckManager.swift          # ACK frame generation & tracking
│   │   ├── RTTEstimator.swift        # RTT measurement & smoothing
│   │   ├── NewRenoCongestionController.swift  # NewReno congestion control
│   │   ├── AntiAmplificationLimiter.swift     # Server amplification attack prevention
│   │   └── SentPacket.swift          # Sent packet metadata
│   │
│   └── QUICTransport/           # UDP integration
│       ├── UDPSocket.swift      # Uses swift-nio-udp
│       └── PacketIO.swift
│
└── Tests/
    ├── QUICCoreTests/
    ├── QUICCryptoTests/
    └── QUICIntegrationTests/
```

## Key Types

### 1. Packet Layer (QUICCore/Packet)

```swift
/// QUIC Connection ID
public struct ConnectionID: Hashable, Sendable {
    public let bytes: Data  // 0-20 bytes

    public static func random(length: Int = 8) -> ConnectionID
}

/// QUIC Version
public struct QUICVersion: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt32

    public static let v1 = QUICVersion(rawValue: 0x00000001)
    public static let v2 = QUICVersion(rawValue: 0x6b3343cf)
}

/// Packet Header (Long or Short form)
public enum PacketHeader: Sendable {
    case long(LongHeader)
    case short(ShortHeader)
}

public struct LongHeader: Sendable {
    public let version: QUICVersion
    public let destinationConnectionID: ConnectionID
    public let sourceConnectionID: ConnectionID
    public let packetType: LongPacketType
    public var packetNumber: UInt64
}

public enum LongPacketType: UInt8, Sendable {
    case initial = 0x00
    case zeroRTT = 0x01
    case handshake = 0x02
    case retry = 0x03
}

public struct ShortHeader: Sendable {
    public let destinationConnectionID: ConnectionID
    public var packetNumber: UInt64
    public let keyPhase: Bool
}
```

### 2. Frame Layer (QUICCore/Frame)

```swift
/// QUIC Frame types
public enum Frame: Sendable {
    case padding
    case ping
    case ack(AckFrame)
    case resetStream(ResetStreamFrame)
    case stopSending(StopSendingFrame)
    case crypto(CryptoFrame)
    case newToken(Data)
    case stream(StreamFrame)
    case maxData(UInt64)
    case maxStreamData(streamID: UInt64, maxData: UInt64)
    case maxStreams(MaxStreamsFrame)
    case dataBlocked(UInt64)
    case streamDataBlocked(streamID: UInt64, limit: UInt64)
    case streamsBlocked(StreamsBlockedFrame)
    case newConnectionID(NewConnectionIDFrame)
    case retireConnectionID(UInt64)
    case pathChallenge(Data)
    case pathResponse(Data)
    case connectionClose(ConnectionCloseFrame)
    case handshakeDone
}

public struct StreamFrame: Sendable {
    public let streamID: UInt64
    public let offset: UInt64
    public let data: Data
    public let fin: Bool
}

public struct AckFrame: Sendable {
    public let largestAcknowledged: UInt64
    public let ackDelay: UInt64
    public let ackRanges: [AckRange]
    public let ecnCounts: ECNCounts?
}
```

### 3. Crypto Layer (QUICCrypto)

```swift
/// Encryption levels (packet number spaces)
public enum EncryptionLevel: Sendable {
    case initial
    case handshake
    case zeroRTT
    case application
}

/// QUIC packet protection
public protocol PacketProtector: Sendable {
    func protect(_ packet: inout Data, packetNumber: UInt64) throws
    func unprotect(_ packet: inout Data) throws -> UInt64
}

/// TLS 1.3 integration
public protocol TLS13Provider: Sendable {
    func startHandshake(isClient: Bool) async throws -> [Data]
    func processHandshakeData(_ data: Data) async throws -> TLSResult
    func exportKeyingMaterial(label: String, context: Data?, length: Int) throws -> Data
    var alpn: String? { get }
    var peerCertificates: [Data] { get }
}

public enum TLSResult: Sendable {
    case continueHandshake([Data])
    case completed(applicationData: Data?)
    case error(Error)
}
```

### 4. Connection API (QUIC)

```swift
/// QUIC Connection configuration
public struct QUICConfiguration: Sendable {
    public var maxIdleTimeout: Duration = .seconds(30)
    public var initialMaxData: UInt64 = 10_000_000
    public var initialMaxStreamDataBidiLocal: UInt64 = 1_000_000
    public var initialMaxStreamDataBidiRemote: UInt64 = 1_000_000
    public var initialMaxStreamDataUni: UInt64 = 1_000_000
    public var initialMaxStreamsBidi: UInt64 = 100
    public var initialMaxStreamsUni: UInt64 = 100
    public var alpn: [String] = ["h3", "libp2p"]
}

/// A QUIC connection with multiplexed streams
public protocol QUICConnection: Sendable {
    var localAddress: SocketAddress? { get }
    var remoteAddress: SocketAddress { get }

    /// Opens a new bidirectional stream
    func openStream() async throws -> QUICStream

    /// Opens a new unidirectional stream
    func openUniStream() async throws -> QUICStream

    /// Accepts incoming streams
    func acceptStream() async throws -> QUICStream

    /// Stream of incoming streams
    var incomingStreams: AsyncStream<QUICStream> { get }

    /// Closes the connection
    func close(error: QUICError?) async
}

/// A single QUIC stream
public protocol QUICStream: Sendable {
    var id: UInt64 { get }
    var isUnidirectional: Bool { get }

    func read() async throws -> Data
    func write(_ data: Data) async throws
    func closeWrite() async throws  // Send FIN
    func reset(errorCode: UInt64) async  // Send RESET_STREAM
}
```

## libp2p Integration

For libp2p, QUIC transport needs special TLS configuration:

### ALPN
```swift
// libp2p uses "libp2p" as ALPN
config.alpn = ["libp2p"]
```

### Peer ID Authentication

libp2p authenticates peers via a TLS extension containing the libp2p public key:

```swift
/// libp2p-specific TLS extension
/// Extension type: 0x0f (reserved for private use)
/// Payload: libp2p public key (protobuf encoded)
public struct Libp2pTLSExtension: Sendable {
    public static let extensionType: UInt16 = 0x0f
    public let publicKey: Data  // Protobuf-encoded libp2p public key
}
```

The certificate used must:
1. Be self-signed
2. Contain the libp2p public key in the extension
3. The certificate's public key signs the libp2p public key

### QUICTransport for libp2p

```swift
/// QUIC Transport for libp2p
/// Implements the Transport protocol from P2PTransport
public final class QUICTransport: Transport, Sendable {
    public var protocols: [[String]] { [["ip4", "udp", "quic-v1"], ["ip6", "udp", "quic-v1"]] }

    public func dial(_ address: Multiaddr) async throws -> any RawConnection {
        // Returns QUICRawConnection (a wrapper that provides RawConnection interface)
    }

    public func listen(_ address: Multiaddr) async throws -> any Listener {
        // Returns QUICListener
    }
}

/// Wrapper to provide RawConnection interface for a QUICConnection
/// Note: For QUIC, this is a "fake" RawConnection that actually provides
/// multiplexed streams. The Security/Mux layers are bypassed.
internal final class QUICRawConnection: RawConnection, Sendable {
    // ...
}
```

## Implementation Phases

### Phase 1: Core Types (QUICCore) ✅
- [x] Varint encoding/decoding
- [x] ConnectionID
- [x] PacketHeader (Long/Short)
- [x] All Frame types (19 types)
- [x] Packet number encoding

### Phase 2: Crypto (QUICCrypto) ✅
- [x] HKDF key derivation
- [x] Initial secrets (derived from Connection ID)
- [x] AES-128-GCM AEAD
- [x] AES-128 Header protection (CommonCrypto/Apple, _CryptoExtras/Linux)
- [x] ChaCha20-Poly1305 AEAD
- [x] ChaCha20 Header protection
- [x] Cross-platform support (Apple/Linux)

### Phase 3: TLS 1.3 Integration ✅
- [x] TLS13Provider protocol
- [x] Full TLS 1.3 state machine (ClientHello → Finished)
- [x] X.509 certificate validation
  - [x] EKU (Extended Key Usage)
  - [x] SAN (Subject Alternative Name)
  - [x] Name Constraints (RFC 5280)
- [x] CryptoStreamManager
- [x] TransportParameters encoding/decoding
- [x] KeySchedule with key update
- [x] Session resumption (PSK)
- [x] 0-RTT early data
- [x] MockTLSProvider for testing (#if DEBUG guarded)
- [ ] libp2p extension support (OID 1.3.6.1.4.1.53594.1.1)

### Phase 4: Connection Layer ✅
- [x] Connection state machine
- [x] QUICConnectionHandler orchestrator
- [x] Packet number space management
- [x] Connection ID management

### Phase 5: Recovery (QUICRecovery) ✅
- [x] RTT estimation (RTTEstimator)
- [x] Loss detection (LossDetector)
- [x] ACK management (AckManager)
- [x] Congestion control (NewRenoCongestionController)
- [x] Anti-amplification limiter (AntiAmplificationLimiter)

### Phase 6: Stream Layer (QUICStream) ✅
- [x] DataStream (send/receive state machines)
- [x] StreamManager (multiplexing, lifecycle)
- [x] FlowController (connection & stream level)
- [x] DataBuffer (out-of-order reassembly)
- [x] STOP_SENDING/RESET_STREAM handling
- [ ] Priority scheduling

### Phase 7: Integration
- [ ] UDP transport integration (swift-nio-udp)
- [ ] Public API (QUICClient, QUICListener)
- [ ] libp2p Transport wrapper
- [ ] Interoperability testing (quiche, quinn)

## Dependencies

```swift
dependencies: [
    // UDP transport
    .package(path: "../swift-nio-udp"),
    // Or: .package(url: "...", from: "1.0.0"),

    // Cryptography
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),

    // Logging
    .package(url: "https://github.com/apple/swift-log.git", from: "1.8.0"),
]
```

## References

- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001: QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002.html)
- [libp2p QUIC spec](https://github.com/libp2p/specs/blob/master/quic/README.md)
- [quiche (Cloudflare)](https://github.com/cloudflare/quiche) - Reference implementation
- [quinn (Rust)](https://github.com/quinn-rs/quinn) - Another reference

## Wire Format Quick Reference

### Variable-Length Integer (Varint)
```
2MSB = 00: 6-bit value (1 byte)
2MSB = 01: 14-bit value (2 bytes)
2MSB = 10: 30-bit value (4 bytes)
2MSB = 11: 62-bit value (8 bytes)
```

### Long Header Format
```
+-+-+-+-+-+-+-+-+
|1|1|T T|X X X X|  Header Form (1) + Fixed (1) + Type (2) + Type-specific (4)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Short Header Format
```
+-+-+-+-+-+-+-+-+
|0|1|S|R|R|K|P P|  Header Form (0) + Fixed (1) + Spin + Reserved + Key Phase + PN Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (8/16/24/32)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Protected Payload (*)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
