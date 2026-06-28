// swift-tools-version: 6.2

import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO for the
// Embedded-clean cores. Lifetimes is enabled in BOTH modes because Span-returning
// members of the P2PCoreBytes dependency require @_lifetime.
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// The `QUIC` facade target's dependencies. The cored Embedded-clean cores + the
// unified provider + the seam-driven `[UInt8]` engine facade (`QUICEngineClient` /
// `QUICEngineConnection`) are present in BOTH builds. The host orchestrator spine
// (`QUICEndpoint` / `ManagedConnection` / `QUICConnectionProtocol` / Foundation /
// NIO) lives in the host adapter targets (`QUICCore` / `QUICCrypto` /
// `QUICConnection` / `QUICStream` / `QUICRecovery` / `QUICTransport`); those are
// dropped under Embedded, where the host spine source is gated
// `#if !hasFeature(Embedded)` and the facade uses only the cores + the
// `DefaultCryptoProvider` seam. This mirrors the proven swift-tls `facadeDependencies`
// split (quic Slice C). The host build is byte-for-byte unchanged.
let quicFacadeDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        // Cored sans-IO engine + cores (dual-build): the `[UInt8]` facade path.
        "QUICConnectionEngineCore",
        "QUICConnectionCore",
        "QUICPacketProtectionCore",
        "QUICWire",
        // Unified crypto provider for the concrete `DefaultCryptoProvider` facade,
        // and the seams the engine facade is generic over.
        .product(name: "P2PCrypto",        package: "swift-p2p-crypto"),
        .product(name: "P2PCoreCrypto",    package: "swift-p2p-core"),
        .product(name: "P2PCoreBytes",     package: "swift-p2p-core"),
        .product(name: "P2PCoreTransport", package: "swift-p2p-core"),
        // RFC 7250 raw-public-key SPKI parsing for the Embedded cert strategy
        // (fail-closed); host path uses swift-certificates via QUICCrypto.
        .product(name: "P2PCoreDER",       package: "swift-p2p-core"),
    ]
    if !embeddedEnabled {
        d += [
            // Host orchestrator spine + Foundation/NIO adapters (gated
            // `#if !hasFeature(Embedded)` in source; dropped from the Embedded build).
            "QUICCore",
            "QUICCrypto",
            "QUICConnection",
            "QUICStream",
            "QUICRecovery",
            "QUICTransport",
            .product(name: "Logging", package: "swift-log"),
        ]
    }
    return d
}()

// Microbenchmarks are opt-in because SwiftPM runs every test target by default,
// while throughput assertions are host-load dependent and not correctness gates.
// Run them with:
//   SWIFT_QUIC_ENABLE_BENCHMARKS=1 swift test --filter QUICBenchmarks
let benchmarkTargets: [Target] = Context.environment["SWIFT_QUIC_ENABLE_BENCHMARKS"] == "1" ? [
    .testTarget(
        name: "QUICBenchmarks",
        dependencies: [
            "QUIC",
            "QUICCore",
            "QUICCrypto",
        ],
        path: "Tests/QUICBenchmarks"
    ),
] : []

let package = Package(
    name: "swift-quic",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26),
    ],
    products: [
        // Main public API
        .library(
            name: "QUIC",
            targets: ["QUIC"]
        ),
        // Tier-3 Embedded-clean wire codec (varint + frame + packet-header codec)
        .library(
            name: "QUICWire",
            targets: ["QUICWire"]
        ),
        // Embedded-clean packet protection (PacketProtector<C,A> / SuiteProtector<C>)
        .library(
            name: "QUICPacketProtectionCore",
            targets: ["QUICPacketProtectionCore"]
        ),
        // Embedded-clean congestion control (CUBIC + Reno) + pacing value types
        .library(
            name: "QUICRecoveryCore",
            targets: ["QUICRecoveryCore"]
        ),
        // Embedded-clean STREAM state machine (send/recv FSM + reassembly + flow control)
        .library(
            name: "QUICStreamCore",
            targets: ["QUICStreamCore"]
        ),
        // Embedded-clean TLS 1.3 key schedule + transcript hash (RFC 8446 §7.1)
        .library(
            name: "QUICTLSCore",
            targets: ["QUICTLSCore"]
        ),
        // Embedded-clean TLS 1.3 signature provider (DefaultCryptoProvider + DER ECDSA)
        .library(
            name: "QUICTLSSignature",
            targets: ["QUICTLSSignature"]
        ),
        // Embedded-clean connection state machines (DPLPMTUD search core)
        .library(
            name: "QUICConnectionCore",
            targets: ["QUICConnectionCore"]
        ),
        // Embedded-clean connection engine (value-type, caller-locked, sans-IO,
        // clock-free) — the cored orchestrator (M11). Drives the cores; the host
        // facade owns the DatagramTransport + AsyncTimer.
        .library(
            name: "QUICConnectionEngineCore",
            targets: ["QUICConnectionEngineCore"]
        ),
        // Core types (no I/O dependencies) — Foundation adapter over QUICWire
        .library(
            name: "QUICCore",
            targets: ["QUICCore"]
        ),
    ],
    dependencies: [
        // UDP transport
        .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.1.3"),

        // Cryptography.
        // Range (not `from: 4.2.0`) so the apple/swift-crypto identity resolves to a
        // single version compatible with swift-p2p-crypto (which floors at 3.x) and
        // swift-certificates (3.12.3..<5.0.0). Adding the swift-p2p-crypto dependency
        // for the unified DefaultCryptoProvider requires the ranges to overlap;
        // 3.12.3..<5.0.0 mirrors swift-certificates' own range. (embedded-first-api.md §2.2)
        .package(url: "https://github.com/apple/swift-crypto.git", "3.12.3"..<"5.0.0"),

        // X.509 Certificates and ASN.1
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.4.3"),

        // Embedded-clean byte primitives (Bytes/ByteReader/ByteWriter) + crypto seam
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", from: "0.1.0"),

        // Unified crypto provider: surfaces `DefaultCryptoProvider` (host
        // swift-crypto / Embedded BoringSSL). Replaces the deleted per-lib
        // QUICFoundationProvider (embedded-first-api.md §2.2). Its vendored
        // BoringSSL is wired as local C targets with renamed symbols, so
        // it coexists with apple/swift-crypto + swift-certificates with no conflict.
        .package(url: "https://github.com/1amageek/swift-p2p-crypto.git", from: "0.1.0"),
    ],
    targets: [
        // MARK: - Embedded-clean wire codec (dual-build: host + Embedded)

        .target(
            name: "QUICWire",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICWire",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean packet protection (dual-build: host + Embedded)

        // The generic packet protector: PacketProtector<C, A> (AEAD payload
        // protection + header protection over the CryptoProvider /
        // HeaderProtectionProvider seam) and the SuiteProtector<C> closed enum
        // that replaces the `any PacketOpener`/`any PacketSealer` existentials.
        .target(
            name: "QUICPacketProtectionCore",
            dependencies: [
                "QUICWire",
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICPacketProtectionCore",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean congestion control + pacing (dual-build: host + Embedded)

        // The value-type congestion controllers (CUBIC RFC 9438 + NewReno RFC 9002 §7)
        // and the token-bucket pacer (RFC 9002 §7.7), with time injected as a
        // monotonic `UInt64` nanosecond parameter. No Foundation/any/Mutex/ContinuousClock.
        .target(
            name: "QUICRecoveryCore",
            dependencies: [
                "QUICWire",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICRecoveryCore",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean STREAM state machine (dual-build: host + Embedded)

        // The value-type QUIC STREAM cores (RFC 9000 §2–4): SendStreamCore /
        // ReceiveStreamCore FSMs, StreamReassemblyBuffer, and FlowControllerCore, over
        // `[UInt8]` payloads. No Foundation/any/Mutex/ContinuousClock. The QUICStream
        // adapter holds these under a Mutex and bridges Data.
        .target(
            name: "QUICStreamCore",
            dependencies: [
                "QUICWire",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICStreamCore",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean TLS 1.3 key schedule (dual-build: host + Embedded)

        // The TLS 1.3 key schedule (RFC 8446 §7.1) generic over `C: CryptoProvider`:
        // early/handshake/master secrets, HKDF-Expand-Label, Derive-Secret, traffic
        // secrets, finished key/verify-data, and the incremental transcript hash, all
        // over `[UInt8]` secrets via the CryptoProvider / KeyDerivation / HashFunction
        // / MessageAuthenticationCode seam. No Foundation/any/Mutex/ContinuousClock/
        // direct-Crypto. The QUICCrypto adapter specialises at C = DefaultCryptoProvider
        // and bridges Data / SymmetricKey / SharedSecret so existing tests are unchanged.
        .target(
            name: "QUICTLSCore",
            dependencies: [
                "QUICWire",
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICTLSCore",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean TLS signature provider (dual-build: host + Embedded)

        // The crypto provider that drives the TLS 1.3 handshake SIGNATURE path:
        // `DefaultCryptoProvider` with ECDSA overridden to DER (RFC 8446 §4.4.3 /
        // X.509 leaf), the encoding go-libp2p / rust-libp2p require on the wire. The
        // shared provider emits RAW `r || s` (correct for Noise/libp2p, wrong for
        // TLS), so this composite DER-encodes ONLY the ECDSA signature and inherits
        // everything else (so handshake keys stay byte-identical). The dual-build
        // counterpart of the host-only `QUICCryptoProvider`. No Foundation, no `any`,
        // no swift-crypto — the DER codec is `P2PCoreDER`.
        .target(
            name: "QUICTLSSignature",
            dependencies: [
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                .product(name: "P2PCoreDER",    package: "swift-p2p-core"),
                .product(name: "P2PCrypto",     package: "swift-p2p-crypto"),
            ],
            path: "Sources/QUICTLSSignature",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean connection state machines (dual-build: host + Embedded)

        // The pure value-type connection state machines that are neither codec nor
        // crypto: currently the DPLPMTUD search core (RFC 8899 / RFC 9000 §14), a
        // `struct` state machine over `Int`/`UInt64`; the transport-parameters codec
        // core (RFC 9000 §18) with a Foundation-free IPv4/IPv6 parser for
        // preferred_address; and the packet parse/serialize core (RFC 9000 §12/§17,
        // RFC 9001 §5) over `[UInt8]`/`ByteReader` driving the cored
        // `SuiteProtector<C>`. No Foundation/any/Mutex/ContinuousClock/inet_pton.
        // The QUICConnection / QUICCore / QUICCrypto adapters hold these and bridge Data.
        .target(
            name: "QUICConnectionCore",
            dependencies: [
                "QUICWire",
                "QUICPacketProtectionCore",
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICConnectionCore",
            swiftSettings: coreSettings
        ),

        // MARK: - Embedded-clean connection engine (dual-build: host + Embedded)

        // The value-type, caller-locked, sans-IO connection orchestration engine
        // `QUICConnectionEngine<C, T>` (M11). It owns the per-connection orchestration
        // ManagedConnection currently does under Mutex — packet-number spaces, key
        // phases, loss recovery + CC + pacing, ACK generation, stream multiplexing,
        // flow control, connection state, idle timeout, path validation — driving the
        // existing cores (NOT reimplementing them). Timers are clock-free: time is
        // injected as `nowNanos: UInt64`, and `handleTimeout(nowNanos:)` returns what
        // to send + the next deadline (mirroring DTLS's `DTLSFlightController`). I/O
        // is inverted: `receive(datagram:from:nowNanos:) -> QUICEngineOutput` and the
        // facade owns the `DatagramTransport` + `AsyncTimer`. Crypto/cert are injected
        // via typed-throws closures; X.509 stays out of the engine. No Foundation,
        // no `any`, no `Mutex`/`ContinuousClock`, no direct-Crypto.
        .target(
            name: "QUICConnectionEngineCore",
            dependencies: [
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                "QUICRecoveryCore",
                "QUICStreamCore",
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICConnectionEngineCore",
            exclude: ["CONTEXT.md"],
            swiftSettings: coreSettings
        ),

        // MARK: - Core Types (Foundation adapter over QUICWire)

        .target(
            name: "QUICCore",
            dependencies: [
                "QUICWire",
                "QUICConnectionCore",
                .product(name: "P2PCoreFoundation", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICCore",
            exclude: ["QUICCore.docc"]
        ),

        // MARK: - Crypto Layer

        .target(
            name: "QUICCrypto",
            dependencies: [
                "QUICCore",
                "QUICConnectionCore",
                "QUICPacketProtectionCore",
                "QUICTLSCore",
                // Unified provider: the host adapter specialises every generic
                // engine at C = DefaultCryptoProvider,
                // replacing the deleted QUICFoundationProvider.
                .product(name: "P2PCrypto", package: "swift-p2p-crypto"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Sources/QUICCrypto",
            exclude: ["CONTEXT.md", "TLS/CONTEXT.md"]
        ),

        // MARK: - Connection Management

        .target(
            name: "QUICConnection",
            dependencies: [
                "QUICCore",
                "QUICConnectionCore",
                "QUICCrypto",
                "QUICStream",
                "QUICRecovery",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/QUICConnection",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - Stream Management

        .target(
            name: "QUICStream",
            dependencies: [
                "QUICCore",
                "QUICStreamCore",
            ],
            path: "Sources/QUICStream",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - Loss Detection & Congestion Control

        .target(
            name: "QUICRecovery",
            dependencies: [
                "QUICCore",
                "QUICRecoveryCore",
            ],
            path: "Sources/QUICRecovery",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - UDP Transport Integration

        .target(
            name: "QUICTransport",
            dependencies: [
                "QUICCore",
                "QUICRecoveryCore",
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
            ],
            path: "Sources/QUICTransport"
        ),

        // MARK: - Main Public API

        // Dual-build: on host the full Foundation/NIO orchestrator spine compiles
        // (the `QUICEndpoint` / `ManagedConnection` API swift-libp2p uses); under
        // Embedded the spine is gated `#if !hasFeature(Embedded)` and only the
        // cores + the `[UInt8]` engine facade (`QUICEngineClient` /
        // `QUICEngineConnection`) compile. Dependencies switch via
        // `quicFacadeDependencies`; `swiftSettings: coreSettings` applies the
        // Embedded feature when `P2P_CORE_EMBEDDED=1` (quic Slice C).
        .target(
            name: "QUIC",
            dependencies: quicFacadeDependencies,
            path: "Sources/QUIC",
            exclude: ["CONTEXT.md", "QUIC.docc"],
            swiftSettings: coreSettings
        ),

        // MARK: - Tests

        .testTarget(
            name: "QUICCoreTests",
            dependencies: ["QUICCore"],
            path: "Tests/QUICCoreTests"
        ),

        .testTarget(
            name: "QUICCryptoTests",
            dependencies: [
                "QUICCrypto",
                "QUICPacketProtectionCore",
                "QUICTLSCore",
                .product(name: "P2PCrypto", package: "swift-p2p-crypto"),
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/QUICCryptoTests"
        ),

        .testTarget(
            name: "QUICTLSSignatureTests",
            dependencies: [
                "QUICTLSSignature",
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Tests/QUICTLSSignatureTests"
        ),

        .testTarget(
            name: "QUICRecoveryTests",
            dependencies: ["QUICRecovery", "QUICCore"],
            path: "Tests/QUICRecoveryTests"
        ),

        .testTarget(
            name: "QUICConnectionEngineCoreTests",
            dependencies: [
                "QUICConnectionEngineCore",
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                .product(name: "P2PCrypto", package: "swift-p2p-crypto"),
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Tests/QUICConnectionEngineCoreTests"
        ),

        .testTarget(
            name: "QUICStreamTests",
            dependencies: ["QUICStream", "QUICCore"],
            path: "Tests/QUICStreamTests"
        ),

        .testTarget(
            name: "QUICTests",
            dependencies: ["QUIC", "QUICRecovery", "QUICTransport"],
            path: "Tests/QUICTests"
        ),

        // Seam-driven engine driver (quic Slice B): exercises QUICEngineConnection
        // (FacadeLock<engine> + DatagramTransport + AsyncTimer) end-to-end over an
        // in-memory loopback transport, proving the facade-on-engine rewire.
        .testTarget(
            name: "QUICEngineConnectionTests",
            dependencies: [
                "QUIC",
                "QUICConnectionEngineCore",
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                .product(name: "P2PCrypto", package: "swift-p2p-crypto"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                .product(name: "P2PCoreTransport", package: "swift-p2p-core"),
            ],
            path: "Tests/QUICEngineConnectionTests"
        ),

    ] + benchmarkTargets
)
