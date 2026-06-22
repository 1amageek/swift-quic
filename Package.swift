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
        // Embedded-clean wire codec (varint + frame + packet-header codec)
        .library(
            name: "QUICCoreCodec",
            targets: ["QUICCoreCodec"]
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
        // Core types (no I/O dependencies) — Foundation adapter over QUICCoreCodec
        .library(
            name: "QUICCore",
            targets: ["QUICCore"]
        ),
    ],
    dependencies: [
        // UDP transport
        .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.1.2"),

        // Cryptography
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),

        // X.509 Certificates and ASN.1
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.4.3"),

        // Embedded-clean byte primitives (Bytes/ByteReader/ByteWriter) + crypto seam
        .package(path: "../swift-p2p-core"),
    ],
    targets: [
        // MARK: - Embedded-clean wire codec (dual-build: host + Embedded)

        .target(
            name: "QUICCoreCodec",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICCoreCodec",
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
                "QUICCoreCodec",
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
                "QUICCoreCodec",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICRecoveryCore",
            swiftSettings: coreSettings
        ),

        // MARK: - Core Types (Foundation adapter over QUICCoreCodec)

        .target(
            name: "QUICCore",
            dependencies: [
                "QUICCoreCodec",
                .product(name: "P2PCoreFoundation", package: "swift-p2p-core"),
            ],
            path: "Sources/QUICCore"
        ),

        // MARK: - Crypto Layer

        .target(
            name: "QUICCrypto",
            dependencies: [
                "QUICCore",
                "QUICPacketProtectionCore",
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

        .target(
            name: "QUIC",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICConnection",
                "QUICStream",
                "QUICRecovery",
                "QUICTransport",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUIC",
            exclude: ["CONTEXT.md"]
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
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/QUICCryptoTests"
        ),

        .testTarget(
            name: "QUICRecoveryTests",
            dependencies: ["QUICRecovery", "QUICCore"],
            path: "Tests/QUICRecoveryTests"
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

        // MARK: - Benchmarks (run separately with: swift test --filter QUICBenchmarks)

        .testTarget(
            name: "QUICBenchmarks",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
            ],
            path: "Tests/QUICBenchmarks"
        ),
    ]
)
