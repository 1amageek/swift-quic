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

## Embedded-First Architecture

swift-quic is **Embedded-first**: the protocol logic lives in a set of
Embedded-clean *core* targets (value-type, caller-locked, sans-IO, generic over
the crypto seam), and the host (Foundation) modules are thin adapters over them.

- `P2P_CORE_EMBEDDED=1` (a `Context.environment` toggle in `Package.swift`)
  switches the core targets into Embedded mode: it enables the experimental
  `Embedded` feature + whole-module optimization (`-wmo`). The `Lifetimes`
  feature is enabled in **both** modes (Span-returning members of the
  `P2PCoreBytes` dependency require `@_lifetime`). The cores are **dual-build**:
  they compile both as ordinary host libraries and under Embedded Swift.
- Embedded rules for the cores: no Foundation, no `any` existentials, no
  `Mutex`/`ContinuousClock`, no direct swift-crypto; all crypto goes through the
  `CryptoProvider` seam; typed throws; closed enums instead of `any`. Cipher-suite
  dispatch is `SuiteProtector<C>` (a closed enum over `PacketProtector<C, A>`),
  which replaced the old `any PacketOpener`/`any PacketSealer` existentials.

> **IMPORTANT — current status.** The canonical TLS path is implemented. Live
> host and Embedded-capable QUIC factories use `swift-tls/QUICTLS`
> backed by `swift-ssl/SSLQUIC`; the former in-package TLS implementation and
> its obsolete integration tests have been removed. The host orchestrator
> remains a host adapter over the cored protocol state, while the portable
> `QUIC` product uses the Embedded-clean engine path. External peer
> interoperability, sanitizer coverage, performance gates, and release
> dependency pinning remain open. Testing mode must not be used as a production
> TLS backend.

## Module Structure

```
swift-quic/
├── Sources/
│   ├── QUICWire/                # Tier-3 Embedded-clean wire codec (dual-build)
│   │   ├── Varint.swift                # QUIC variable-length integer
│   │   ├── ProtocolLimits.swift        # RFC-compliant protocol limits
│   │   ├── SafeConversions.swift       # Overflow-checked integer conversions
│   │   ├── QUICWireError.swift
│   │   ├── Packet/
│   │   │   ├── PacketHeader.swift      # Long/Short header
│   │   │   ├── ConnectionID.swift
│   │   │   └── Version.swift           # salt / retry-integrity constants
│   │   └── Frame/
│   │       ├── Frame.swift             # Frame enum + FrameType
│   │       ├── FrameCodec.swift        # StandardFrameCodec
│   │       ├── FrameTypes.swift
│   │       └── FrameSize.swift
│   │
│   ├── QUICPacketProtectionCore/  # Embedded-clean packet protection (dual-build)
│   │   ├── PacketProtector.swift       # PacketProtector<C, A> (AEAD + HP over the seam)
│   │   ├── SuiteProtector.swift        # closed cipher-suite enum (no `any`)
│   │   └── QUICKeyDerivation.swift     # RFC 9001 §5.1 key material
│   │
│   ├── QUICRecoveryCore/        # Embedded-clean congestion control + pacing (dual-build)
│   │   ├── LossDetectorCore.swift      # sorted-array packet/time threshold detection
│   │   ├── RTTEstimatorCore.swift
│   │   ├── CubicCore.swift             # CUBIC (RFC 9438)
│   │   ├── NewRenoCore.swift           # NewReno (RFC 9002 §7)
│   │   ├── PacerCore.swift             # token-bucket pacing (RFC 9002 §7.7)
│   │   └── AntiAmplificationCore.swift
│   │
│   ├── QUICStreamCore/          # Embedded-clean STREAM state machine (dual-build)
│   │   ├── SendStreamCore.swift        # send FSM
│   │   ├── ReceiveStreamCore.swift     # receive FSM
│   │   ├── StreamReassemblyBuffer.swift
│   │   └── FlowControllerCore.swift
│   │
│   ├── QUICConnectionCore/      # Embedded-clean connection state machines (dual-build)
│   │   ├── PathMTUSearchCore.swift     # DPLPMTUD (RFC 8899 / RFC 9000 §14)
│   │   ├── TransportParameterCodecCore.swift  # RFC 9000 §18
│   │   ├── IPAddressCodec.swift        # Foundation-free IPv4/IPv6 parser
│   │   ├── PacketParsingCore.swift     # packet parse/serialize over SuiteProtector<C>
│   │   ├── ConnectionStateCore.swift
│   │   ├── IdleTimeoutCore.swift
│   │   └── PathValidationCore.swift
│   │
│   ├── QUICCore/                # Foundation adapter over QUICWire + QUICConnectionCore
│   │   ├── Packet/PacketCodec.swift    # packet encoding with encryption + padding
│   │   ├── Compat/                     # Data-based views over the wire codec
│   │   └── ...
│   │
│   ├── QUICCrypto/              # Packet-protection and host adapter (TLS via swift-ssl)
│   │   ├── TLS/SwiftSSLQUICTLSProvider.swift # canonical session adapter
│   │   ├── InitialSecrets.swift        # Initial key derivation, KeyMaterial, QUICCipherSuite
│   │   ├── AEAD.swift                  # AES-GCM / ChaCha20-Poly1305 over PacketProtector<C,A>
│   │   ├── CryptoState.swift           # CryptoContext, HeaderProtection
│   │   └── QUICCryptoProvider.swift    # the unified C = DefaultCryptoProvider (+ DER-ECDSA)
│   │
│   ├── QUICConnection/          # Connection orchestration adapter (over QUICConnectionCore)
│   │   ├── QUICConnectionHandler.swift # per-connection state machine, TLS integration
│   │   └── ...
│   │
│   ├── QUICStream/              # Stream adapter (over QUICStreamCore; RFC 9000 §2-4)
│   │   ├── DataStream.swift       # holds Send/ReceiveStreamCore under Mutex, bridges Data
│   │   ├── StreamManager.swift    # Stream multiplexing, creation, lifecycle
│   │   ├── FlowController.swift   # wraps FlowControllerCore
│   │   ├── DataBuffer.swift       # wraps StreamReassemblyBuffer
│   │   └── StreamState.swift
│   │
│   ├── QUICRecovery/            # Loss detection adapter (over QUICRecoveryCore; RFC 9002)
│   │   ├── LossDetector.swift        # holds LossDetectorCore under Mutex
│   │   ├── AckManager.swift          # ACK frame generation & tracking
│   │   ├── RTTEstimator.swift        # wraps RTTEstimatorCore
│   │   ├── NewRenoCongestionController.swift  # wraps NewRenoCore
│   │   ├── CubicCongestionController.swift     # wraps CubicCore
│   │   ├── AntiAmplificationLimiter.swift     # wraps AntiAmplificationCore
│   │   └── SentPacket.swift
│   │
│   ├── QUICTransport/           # UDP integration (uses swift-nio-udp)
│   │
│   └── QUIC/                    # Main public API (host orchestrator — NOT yet cored)
│       ├── QUICEndpoint.swift     # Server/Client endpoint, I/O loops
│       ├── ManagedConnection.swift# high-level connection (async streams)
│       ├── ManagedStream.swift
│       ├── ConnectionRouter.swift # DCID-based routing
│       ├── PacketProcessor.swift  # packet encryption/decryption over SuiteProtector<C>
│       ├── TimerManager.swift     # loss-detection / PTO timers
│       └── QUICConfiguration.swift
│
└── Tests/
    ├── QUICCoreTests/
    ├── QUICCryptoTests/      # also exercises QUICPacketProtectionCore
    ├── QUICRecoveryTests/
    ├── QUICStreamTests/
    ├── QUICTests/           # integration
    └── QUICBenchmarks/
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

/// QUIC packet protection (Embedded-clean, in QUICPacketProtectionCore).
///
/// The generic `PacketProtector<C, A>` carries one keyed AEAD `A` plus the
/// packet-protection IV and header-protection key, performing seal/open and
/// header protection over the `CryptoProvider` / `HeaderProtectionProvider` seam.
public struct PacketProtector<C: CryptoProvider, A: AEAD>: Sendable {
    public func seal(_ plaintext: [UInt8], packetNumber: UInt64, header: [UInt8]) throws(PacketProtectionError) -> [UInt8]
    public func open(_ ciphertext: [UInt8], packetNumber: UInt64, header: [UInt8]) throws(PacketProtectionError) -> [UInt8]
    public func applyHeaderProtection(sample: [UInt8], firstByte: UInt8, packetNumberBytes: [UInt8]) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8])
    public func removeHeaderProtection(sample: [UInt8], firstByte: UInt8, packetNumberBytes: [UInt8]) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8])
}

/// Cipher-suite dispatch is a closed enum — NOT `any PacketOpener`/`any PacketSealer`.
/// QUIC mandates AES-128-GCM and ChaCha20-Poly1305 (RFC 9001 §5.3); key updates
/// may add AES-256-GCM. The adapter instantiates it at C = QUICCryptoProvider.
public enum SuiteProtector<C: CryptoProvider>: Sendable {
    case aes128GCM(PacketProtector<C, C.AESGCM128>)
    case aes256GCM(PacketProtector<C, C.AESGCM256>)
    case chaCha20Poly1305(PacketProtector<C, C.ChaChaPoly>)
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

    /// Stream of incoming streams from the remote peer.
    ///
    /// Use this to receive streams initiated by the remote peer:
    /// ```swift
    /// // Process all incoming streams
    /// for await stream in connection.incomingStreams {
    ///     Task { await handleStream(stream) }
    /// }
    ///
    /// // Accept a single stream
    /// var iterator = connection.incomingStreams.makeAsyncIterator()
    /// if let stream = await iterator.next() {
    ///     // handle stream
    /// }
    /// ```
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
- [x] AES-128-GCM AEAD (over PacketProtector<C, A>)
- [x] AES Header protection (routed through the HeaderProtectionProvider seam and the common DefaultCryptoProvider)
- [x] ChaCha20-Poly1305 AEAD
- [x] ChaCha20 Header protection (via the seam)
- [x] Cross-platform support through the same swift-crypto fork

### Phase 3: TLS 1.3 Integration (canonical provider implemented)
- [x] `TLS13Provider` host contract backed by `SwiftSSLQUICTLSProvider`
- [x] Full TLS 1.3 state machine through `swift-tls/QUICTLS` and
      `swift-ssl/SSLQUIC` (ClientHello → Finished)
- [x] X.509 certificate validation
  - [x] EKU (Extended Key Usage)
  - [x] SAN (Subject Alternative Name)
  - [x] Name Constraints (RFC 5280)
- [x] CryptoStreamManager
- [x] TransportParameters encoding/decoding
- [x] KeySchedule with key update
- [x] Session resumption (PSK)
- [x] 0-RTT early data
- [ ] Mock TLS provider (testing mode is fail-closed until a canonical test
      provider is supplied)
- [x] QUIC TLS handshake + key schedule owned by `swift-ssl/SSLQUIC`
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

### Phase 7: Integration ✅
- [x] UDP transport integration (swift-nio-udp)
- [x] Public API — entry point is `QUICEndpoint` (`serve` / `dial`), with
      `ManagedConnection` / `ManagedStream` as the high-level surface.
      (There is no `QUICClient` / `QUICListener` type.)
- [x] libp2p Transport wrapper
- [x] Interoperability testing (quinn, ngtcp2; Docker-based)

### Phase 8: Embedded-first re-tier (cores) — canonical boundary implemented
- [x] QUICWire (Tier-3 wire codec) extracted from QUICCore
- [x] QUICPacketProtectionCore (PacketProtector<C,A> / SuiteProtector<C>)
- [x] QUICRecoveryCore (CUBIC + NewReno + pacing)
- [x] QUICStreamCore (Send/Receive FSMs + reassembly + flow control)
- [x] `swift-tls/QUICTLS` adapter over `swift-ssl/SSLQUIC`
- [x] QUICConnectionCore (DPLPMTUD + transport-params codec + packet parse/serialize)
- [x] Crypto unified on DefaultCryptoProvider (QUICFoundationProvider deleted)
- [x] Tagged release of the cores (milestone "M8")
- [x] Portable `QUIC` product compiles against the canonical session provider
- [ ] Complete host-orchestrator migration to the cored connection engine;
      this is independent of TLS mechanism ownership and remains a separate
      release gate.

## Dependencies

Verify against `Package.swift` (Swift tools 6.4; platforms macOS/iOS/tvOS/watchOS/visionOS v26).

```swift
dependencies: [
    // UDP transport.
    .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.1.4"),

    // Public session contracts and Pure Swift TLS mechanism.
    .package(url: "https://github.com/1amageek/swift-tls.git", branch: "main"),
    .package(url: "https://github.com/1amageek/swift-ssl.git", branch: "main"),

    // Cryptography shared by Native, WASM, and Embedded.
    .package(url: "https://github.com/1amageek/swift-crypto.git", branch: "main"),

    // X.509 + ASN.1
    .package(url: "https://github.com/1amageek/swift-certificates.git", branch: "main"),
    .package(url: "https://github.com/1amageek/swift-asn1.git", branch: "main"),

    // Logging
    .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),

    // Documentation
    .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.4.3"),

    // Embedded-clean primitives, crypto seam, and DefaultCryptoProvider.
    .package(url: "https://github.com/1amageek/swift-p2p-core.git", branch: "main"),
]
```

The unified provider: `QUICCryptoProvider` is the host adapter's concrete crypto
provider — it mirrors `DefaultCryptoProvider` except ECDSA signatures are
DER-encoded for the TLS path. Every generic
core engine is specialised at `C = QUICCryptoProvider` in the host adapters.

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
