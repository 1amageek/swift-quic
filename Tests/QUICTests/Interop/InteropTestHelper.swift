/// Interoperability Test Helper
///
/// Utilities for testing QUIC interoperability with external implementations.

import Foundation
import Testing
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto

// MARK: - Interop Test Helper

/// Helper utilities for interoperability testing
public enum InteropTestHelper {

    /// Check if Docker interop services are running
    public static func isDockerRunning() -> Bool {
        // First try to find docker directory relative to project
        guard let dockerDir = findDockerDirectory() else {
            // Fall back to checking if quinn-interop container is running directly
            return isContainerRunning(named: "quinn-interop")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["docker", "compose", "ps", "--services", "--filter", "status=running"]
        process.currentDirectoryURL = dockerDir

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("quinn")
        } catch {
            // Fall back to checking container directly
            return isContainerRunning(named: "quinn-interop")
        }
    }

    /// Check if a specific Docker container is running
    private static func isContainerRunning(named containerName: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["docker", "ps", "--filter", "name=\(containerName)", "--filter", "status=running", "-q"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return !output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        } catch {
            return false
        }
    }

    /// Find the docker directory in the project
    private static func findDockerDirectory() -> URL? {
        // Try multiple strategies to find the docker directory

        // Strategy 1: Search upward from current directory
        var currentDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for _ in 0..<10 {
            let dockerDir = currentDir.appendingPathComponent("docker")
            if FileManager.default.fileExists(atPath: dockerDir.appendingPathComponent("docker-compose.yml").path) {
                return dockerDir
            }
            currentDir = currentDir.deletingLastPathComponent()
        }

        // Strategy 2: Search upward from source file location
        var sourceDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            let dockerDir = sourceDir.appendingPathComponent("docker")
            if FileManager.default.fileExists(atPath: dockerDir.appendingPathComponent("docker-compose.yml").path) {
                return dockerDir
            }
            sourceDir = sourceDir.deletingLastPathComponent()
        }

        return nil
    }

    /// Quinn server address (default interop port)
    public static let quinnServerAddress = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

    /// ngtcp2 server address
    public static let ngtcp2ServerAddress = SocketAddress(ipAddress: "127.0.0.1", port: 4434)

    /// Check if ngtcp2 Docker service is running
    public static func isNgtcp2Running() -> Bool {
        isContainerRunning(named: "ngtcp2-interop")
    }

    /// Create a test QUIC configuration for interop testing
    /// Uses real TLS13Handler with peer verification disabled for self-signed certs
    public static func makeTestConfiguration() -> QUICConfiguration {
        var config = QUICConfiguration.development {
            // Create TLS configuration that allows self-signed certificates
            var tlsConfig = TLSConfiguration.client(
                serverName: "localhost",
                alpnProtocols: ["hq-interop", "h3"]  // Quinn interop uses hq-interop
            )
            tlsConfig.verifyPeer = false  // Allow self-signed certificates
            tlsConfig.allowSelfSigned = true
            return TLS13Handler(configuration: tlsConfig)
        }
        config.version = .v1
        return config
    }

    /// Create a test QUIC configuration with Mock TLS (for unit tests)
    public static func makeMockConfiguration() -> QUICConfiguration {
        var config = QUICConfiguration.testing()
        config.verifyPeer = false
        config.version = .v1
        return config
    }
}

// MARK: - Test Traits

extension Tag {
    /// Tests requiring Docker services
    @Tag static var docker: Self

    /// Tests requiring external QUIC servers
    @Tag static var interop: Self
}

/// Trait that enables test only when Docker is running
struct DockerRequired: TestTrait {
    static var isRecursive: Bool { false }

    var isEnabled: Bool {
        InteropTestHelper.isDockerRunning()
    }

    var skipMessage: String {
        "Docker interop services not running. Run: cd docker && docker compose up -d"
    }
}

extension Trait where Self == DockerRequired {
    /// Requires Docker interop services to be running
    static var requiresDocker: Self { DockerRequired() }
}
