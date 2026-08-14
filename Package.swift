// swift-tools-version: 6.4

import PackageDescription

let embeddedEnabled = Context.environment["SWIFT_NETWORKING_EMBEDDED"] == "1"

let coreSettings: [SwiftSetting] = {
    var settings: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        settings += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return settings
}()

let benchmarksEnabled = Context.environment["SWIFT_QUIC_ENABLE_BENCHMARKS"] == "1"
let wasmValidationEnabled = Context.environment["SWIFT_QUIC_ENABLE_WASM_VALIDATION"] == "1"

let benchmarkProducts: [Product] = benchmarksEnabled ? [
    .executable(name: "quic-benchmarks", targets: ["QUICBenchmarks"]),
] : []

let benchmarkTargets: [Target] = benchmarksEnabled ? [
    .executableTarget(
        name: "QUICBenchmarks",
        dependencies: [
            "QUICWire",
            "QUICPacketProtectionCore",
            "QUICConnectionCore",
            .product(name: "NetworkingCore", package: "swift-networking"),
        ],
        path: "Benchmarks/QUICBenchmarks",
        swiftSettings: coreSettings
    ),
] : []

let wasmValidationProducts: [Product] = wasmValidationEnabled ? [
    .executable(name: "quic-wasm-validation", targets: ["QUICWASMValidation"]),
] : []

let wasmValidationTargets: [Target] = wasmValidationEnabled ? [
    .executableTarget(
        name: "QUICWASMValidation",
        dependencies: [
            "QUIC",
            "QUICWire",
            "QUICConnectionCore",
            "QUICConnectionEngineCore",
        ],
        path: "Validation/QUICWASMValidation",
        swiftSettings: coreSettings
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
        .library(name: "QUIC", targets: ["QUIC"]),
        .library(name: "QUICWire", targets: ["QUICWire"]),
        .library(name: "QUICPacketProtectionCore", targets: ["QUICPacketProtectionCore"]),
        .library(name: "QUICRecoveryCore", targets: ["QUICRecoveryCore"]),
        .library(name: "QUICStreamCore", targets: ["QUICStreamCore"]),
        .library(name: "QUICConnectionCore", targets: ["QUICConnectionCore"]),
        .library(name: "QUICConnectionEngineCore", targets: ["QUICConnectionEngineCore"]),
    ] + benchmarkProducts + wasmValidationProducts,
    dependencies: [
        .package(url: "https://github.com/1amageek/swift-tls.git", from: "2.0.0"),
        .package(url: "https://github.com/1amageek/swift-ssl.git", from: "0.2.0"),
        .package(url: "https://github.com/1amageek/swift-networking.git", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: "QUICWire",
            dependencies: [
                .product(name: "NetworkingCore", package: "swift-networking"),
            ],
            path: "Sources/QUICWire",
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUICPacketProtectionCore",
            dependencies: [
                "QUICWire",
                .product(name: "NetworkingCore", package: "swift-networking"),
                .product(name: "SSLCrypto", package: "swift-ssl"),
            ],
            path: "Sources/QUICPacketProtectionCore",
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUICRecoveryCore",
            dependencies: ["QUICWire"],
            path: "Sources/QUICRecoveryCore",
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUICStreamCore",
            dependencies: ["QUICWire"],
            path: "Sources/QUICStreamCore",
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUICConnectionCore",
            dependencies: [
                "QUICWire",
                "QUICPacketProtectionCore",
                .product(name: "NetworkingCore", package: "swift-networking"),
            ],
            path: "Sources/QUICConnectionCore",
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUICConnectionEngineCore",
            dependencies: [
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                "QUICRecoveryCore",
                "QUICStreamCore",
            ],
            path: "Sources/QUICConnectionEngineCore",
            exclude: ["CONTEXT.md"],
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUIC",
            dependencies: [
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                "QUICRecoveryCore",
                "QUICStreamCore",
                "QUICConnectionEngineCore",
                .product(name: "QUICTLS", package: "swift-tls"),
                .product(name: "TLSTypes", package: "swift-networking"),
                .product(name: "NetworkingCore", package: "swift-networking"),
                .product(name: "NetworkingDatagram", package: "swift-networking"),
                .product(name: "NetworkingTime", package: "swift-networking"),
            ],
            path: "Sources/QUIC",
            exclude: [
                "CONTEXT.md",
                "QUIC.docc",
            ],
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "QUICWireTests",
            dependencies: ["QUICWire"],
            path: "Tests/QUICWireTests"
        ),
        .testTarget(
            name: "QUICPacketProtectionCoreTests",
            dependencies: [
                "QUICPacketProtectionCore",
                .product(name: "NetworkingCore", package: "swift-networking"),
            ],
            path: "Tests/QUICPacketProtectionCoreTests"
        ),
        .testTarget(
            name: "QUICRecoveryCoreTests",
            dependencies: ["QUICRecoveryCore"],
            path: "Tests/QUICRecoveryCoreTests"
        ),
        .testTarget(
            name: "QUICStreamCoreTests",
            dependencies: ["QUICStreamCore", "QUICWire"],
            path: "Tests/QUICStreamCoreTests"
        ),
        .testTarget(
            name: "QUICConnectionCoreTests",
            dependencies: ["QUICConnectionCore", "QUICWire"],
            path: "Tests/QUICConnectionCoreTests"
        ),
        .testTarget(
            name: "QUICConnectionEngineCoreTests",
            dependencies: [
                "QUICConnectionEngineCore",
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                .product(name: "NetworkingCore", package: "swift-networking"),
            ],
            path: "Tests/QUICConnectionEngineCoreTests"
        ),
        .testTarget(
            name: "QUICEngineConnectionTests",
            dependencies: [
                "QUIC",
                "QUICConnectionEngineCore",
                "QUICWire",
                "QUICPacketProtectionCore",
                "QUICConnectionCore",
                .product(name: "NetworkingCore", package: "swift-networking"),
                .product(name: "NetworkingDatagram", package: "swift-networking"),
                .product(name: "NetworkingTime", package: "swift-networking"),
                .product(name: "QUICTLS", package: "swift-tls"),
                .product(name: "SSLCore", package: "swift-ssl"),
                .product(name: "SSLCrypto", package: "swift-ssl"),
                .product(name: "SSLX509", package: "swift-ssl"),
            ],
            path: "Tests/QUICEngineConnectionTests"
        ),
    ] + benchmarkTargets + wasmValidationTargets
)
