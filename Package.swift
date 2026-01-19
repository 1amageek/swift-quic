// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "swift-quic",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        // Main public API
        .library(
            name: "QUIC",
            targets: ["QUIC"]
        ),
        // Core types (no I/O dependencies)
        .library(
            name: "QUICCore",
            targets: ["QUICCore"]
        ),
    ],
    dependencies: [
        // UDP transport
        .package(url: "https://github.com/1amageek/swift-nio-udp.git", from: "1.0.0"),

        // Cryptography
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),
    ],
    targets: [
        // MARK: - Core Types (No I/O)

        .target(
            name: "QUICCore",
            dependencies: [],
            path: "Sources/QUICCore"
        ),

        // MARK: - Crypto Layer

        .target(
            name: "QUICCrypto",
            dependencies: [
                "QUICCore",
                .product(name: "Crypto", package: "swift-crypto"),
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
            ],
            path: "Sources/QUICRecovery",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - UDP Transport Integration

        .target(
            name: "QUICTransport",
            dependencies: [
                "QUICCore",
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
            dependencies: ["QUICCrypto"],
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
