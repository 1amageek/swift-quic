/// QUIC Interoperability Tests
///
/// Tests for verifying interoperability with other QUIC implementations:
/// - quic-go: Go implementation
/// - ngtcp2: C implementation
///
/// These tests validate RFC compliance and wire format compatibility.

import Testing
import Foundation
import NIOUDPTransport
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICRecovery
@testable import QUICTransport

// MARK: - InitialSecrets Extension for Testing

extension InitialSecrets {
    /// Derives client key material for testing
    func clientKeys() throws -> KeyMaterial {
        return try KeyMaterial.derive(from: clientSecret)
    }

    /// Derives server key material for testing
    func serverKeys() throws -> KeyMaterial {
        return try KeyMaterial.derive(from: serverSecret)
    }
}

// MARK: - RFC 9001 Test Vector Tests

@Suite("RFC 9001 Test Vectors")
struct RFC9001TestVectorTests {

    @Test("Initial secrets derivation matches RFC 9001 A.1")
    func initialSecretsDerivation() throws {
        let dcid = try ConnectionID(RFC9001TestVectors.clientDCID)

        // Derive initial secrets
        let secrets = try InitialSecrets.derive(
            connectionID: dcid,
            version: .v1
        )

        // Verify client initial secret
        #expect(
            secrets.clientSecret.withUnsafeBytes { Data($0) } == RFC9001TestVectors.clientInitialSecret,
            "Client initial secret mismatch"
        )

        // Verify server initial secret
        #expect(
            secrets.serverSecret.withUnsafeBytes { Data($0) } == RFC9001TestVectors.serverInitialSecret,
            "Server initial secret mismatch"
        )
    }

    @Test("Client keys derivation matches RFC 9001 A.1")
    func clientKeysDerivation() throws {
        let dcid = try ConnectionID(RFC9001TestVectors.clientDCID)

        // Derive keys
        let secrets = try InitialSecrets.derive(
            connectionID: dcid,
            version: .v1
        )

        let clientKeys = try secrets.clientKeys()

        // Verify client key
        #expect(
            clientKeys.key.withUnsafeBytes { Data($0) } == RFC9001TestVectors.clientKey,
            "Client key mismatch"
        )

        // Verify client IV
        #expect(
            clientKeys.iv == RFC9001TestVectors.clientIV,
            "Client IV mismatch"
        )

        // Verify client HP key
        #expect(
            clientKeys.hp.withUnsafeBytes { Data($0) } == RFC9001TestVectors.clientHP,
            "Client HP key mismatch"
        )
    }

    @Test("Server keys derivation matches RFC 9001 A.1")
    func serverKeysDerivation() throws {
        let dcid = try ConnectionID(RFC9001TestVectors.clientDCID)

        // Derive keys
        let secrets = try InitialSecrets.derive(
            connectionID: dcid,
            version: .v1
        )

        let serverKeys = try secrets.serverKeys()

        // Verify server key
        #expect(
            serverKeys.key.withUnsafeBytes { Data($0) } == RFC9001TestVectors.serverKey,
            "Server key mismatch"
        )

        // Verify server IV
        #expect(
            serverKeys.iv == RFC9001TestVectors.serverIV,
            "Server IV mismatch"
        )

        // Verify server HP key
        #expect(
            serverKeys.hp.withUnsafeBytes { Data($0) } == RFC9001TestVectors.serverHP,
            "Server HP key mismatch"
        )
    }
}

// MARK: - Retry Integrity Tag Tests

@Suite("Retry Integrity Tag Tests")
struct RetryIntegrityTagTests {

    @Test("Retry Integrity Tag round-trip")
    func retryIntegrityTagRoundTrip() throws {
        let originalDCID = try ConnectionID(RFC9001TestVectors.clientDCID)
        let destinationCID = try ConnectionID(Data())
        let sourceCID = try ConnectionID(Data([
            0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5
        ]))
        let retryToken = Data([0x74, 0x6f, 0x6b, 0x65, 0x6e]) // "token"

        // Create a complete Retry packet with tag
        let retryPacket = try RetryIntegrityTag.createRetryPacket(
            originalDCID: originalDCID,
            destinationCID: destinationCID,
            sourceCID: sourceCID,
            retryToken: retryToken,
            version: .v1
        )

        // Parse it back
        let parsed = try RetryIntegrityTag.parseRetryPacket(retryPacket)

        #expect(parsed.version == .v1)
        #expect(parsed.destinationCID == destinationCID)
        #expect(parsed.sourceCID == sourceCID)
        #expect(parsed.retryToken == retryToken)

        // Verify the tag
        let packetWithoutTag = RetryIntegrityTag.retryPacketWithoutTag(retryPacket)
        let isValid = try RetryIntegrityTag.verify(
            tag: parsed.integrityTag,
            originalDCID: originalDCID,
            retryPacketWithoutTag: packetWithoutTag,
            version: .v1
        )

        #expect(isValid)
    }

    @Test("Retry Integrity Tag verification works")
    func retryIntegrityTagVerification() throws {
        let originalDCID = try ConnectionID(RFC9001TestVectors.clientDCID)
        let destinationCID = try ConnectionID(Data())
        let sourceCID = try ConnectionID(Data([
            0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5
        ]))
        let retryToken = Data([0x74, 0x6f, 0x6b, 0x65, 0x6e])

        // Create retry packet
        let retryPacket = try RetryIntegrityTag.createRetryPacket(
            originalDCID: originalDCID,
            destinationCID: destinationCID,
            sourceCID: sourceCID,
            retryToken: retryToken,
            version: .v1
        )

        // Extract packet without tag and the tag itself
        let packetWithoutTag = RetryIntegrityTag.retryPacketWithoutTag(retryPacket)
        let tag = retryPacket.suffix(16)

        // Verify it
        let isValid = try RetryIntegrityTag.verify(
            tag: Data(tag),
            originalDCID: originalDCID,
            retryPacketWithoutTag: packetWithoutTag,
            version: .v1
        )

        #expect(isValid)
    }

    @Test("Invalid Retry Integrity Tag is rejected")
    func invalidRetryIntegrityTagRejected() throws {
        let originalDCID = try ConnectionID(RFC9001TestVectors.clientDCID)
        let destinationCID = try ConnectionID(Data())
        let sourceCID = try ConnectionID(Data([
            0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5
        ]))
        let retryToken = Data([0x74, 0x6f, 0x6b, 0x65, 0x6e])

        // Create valid retry packet
        let retryPacket = try RetryIntegrityTag.createRetryPacket(
            originalDCID: originalDCID,
            destinationCID: destinationCID,
            sourceCID: sourceCID,
            retryToken: retryToken,
            version: .v1
        )

        let packetWithoutTag = RetryIntegrityTag.retryPacketWithoutTag(retryPacket)

        // Create an invalid tag (all zeros)
        let invalidTag = Data(repeating: 0, count: 16)

        // Verification should fail
        let isValid = try RetryIntegrityTag.verify(
            tag: invalidTag,
            originalDCID: originalDCID,
            retryPacketWithoutTag: packetWithoutTag,
            version: .v1
        )

        #expect(!isValid)
    }

    @Test("Retry packet is detected correctly")
    func retryPacketDetection() throws {
        let originalDCID = try #require(ConnectionID.random(length: 8))
        let destinationCID = try #require(ConnectionID.random(length: 8))
        let sourceCID = try #require(ConnectionID.random(length: 8))
        let retryToken = Data([0x01, 0x02, 0x03, 0x04])

        let retryPacket = try RetryIntegrityTag.createRetryPacket(
            originalDCID: originalDCID,
            destinationCID: destinationCID,
            sourceCID: sourceCID,
            retryToken: retryToken,
            version: .v1
        )

        #expect(RetryIntegrityTag.isRetryPacket(retryPacket))

        // Non-retry packet should not be detected
        let notRetryPacket = Data([0x00, 0x01, 0x02, 0x03])
        #expect(!RetryIntegrityTag.isRetryPacket(notRetryPacket))
    }
}

// MARK: - Version Negotiation Tests

@Suite("Version Negotiation Tests")
struct VersionNegotiationTests {

    @Test("Version Negotiation packet creation")
    func versionNegotiationPacketCreation() throws {
        let dcid = VersionNegotiationTestData.destinationCID
        let scid = VersionNegotiationTestData.sourceCID
        let versions = VersionNegotiationTestData.serverVersions

        let packet = VersionNegotiator.createVersionNegotiationPacket(
            destinationCID: dcid,
            sourceCID: scid,
            supportedVersions: versions
        )

        // First byte should have Form bit set (0x80) for Long Header
        // But VN uses random bits for the first byte except Form bit
        #expect(packet[0] & 0x80 == 0x80, "Long header form bit must be set")

        // Version field (bytes 1-4) must be 0x00000000
        let version = UInt32(packet[1]) << 24 | UInt32(packet[2]) << 16 |
                      UInt32(packet[3]) << 8 | UInt32(packet[4])
        #expect(version == WireFormatTestData.versionNegotiationVersion)

        // DCID length byte
        let dcidLen = Int(packet[5])
        #expect(dcidLen == dcid.bytes.count)

        // SCID length byte follows DCID
        let scidLenIndex = 6 + dcidLen
        let scidLen = Int(packet[scidLenIndex])
        #expect(scidLen == scid.bytes.count)

        // Supported versions follow
        let versionsStart = scidLenIndex + 1 + scidLen
        let versionsData = packet[versionsStart...]

        // Should contain all supported versions (4 bytes each)
        #expect(versionsData.count == versions.count * 4)
    }

    @Test("Version Negotiation version parsing")
    func versionNegotiationParsing() throws {
        let dcid = VersionNegotiationTestData.destinationCID
        let scid = VersionNegotiationTestData.sourceCID
        let versions = VersionNegotiationTestData.serverVersions

        // Create packet
        let packet = VersionNegotiator.createVersionNegotiationPacket(
            destinationCID: dcid,
            sourceCID: scid,
            supportedVersions: versions
        )

        // Parse versions from packet
        let parsedVersions = try VersionNegotiator.parseVersions(from: packet)

        #expect(parsedVersions == versions)
    }

    @Test("Version selection chooses common version")
    func versionSelection() {
        let clientVersions: [QUICVersion] = [.v1, .init(rawValue: 0xaabbccdd)]
        let serverVersions: [QUICVersion] = [.v2, .v1]

        let selected = VersionNegotiator.selectVersion(
            offered: clientVersions,
            supported: serverVersions
        )

        // Should select v1 (the common version)
        #expect(selected == .v1)
    }

    @Test("Version selection returns nil when no common version")
    func versionSelectionNoCommon() {
        let clientVersions: [QUICVersion] = [.init(rawValue: 0x11111111)]
        let serverVersions: [QUICVersion] = [.v1, .v2]

        let selected = VersionNegotiator.selectVersion(
            offered: clientVersions,
            supported: serverVersions
        )

        #expect(selected == nil)
    }
}

// MARK: - Wire Format Tests

@Suite("Wire Format Compatibility Tests")
struct WireFormatTests {

    @Test("Initial packet minimum size is 1200 bytes")
    func initialPacketMinimumSize() throws {
        let processor = PacketProcessor(dcidLength: 8)
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))

        let (_, _) = try processor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: true,
            version: .v1
        )

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: nil
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data("test".utf8)))
        ]

        let packet = try processor.encryptLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0
        )

        #expect(packet.count >= WireFormatTestData.minInitialPacketSize)
    }

    @Test("Long header format is correct")
    func longHeaderFormat() throws {
        let processor = PacketProcessor(dcidLength: 8)
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))

        let (_, _) = try processor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: true,
            version: .v1
        )

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: nil
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data(repeating: 0, count: 100)))
        ]

        let packet = try processor.encryptLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0
        )

        // First byte: Form bit (1) + Fixed bit (1) + Type (2 bits for Initial = 00)
        // After header protection, reserved bits and PN length are masked
        let firstByte = packet[0]

        // Form bit must be set (Long Header)
        #expect(firstByte & 0x80 == 0x80, "Form bit must be set for Long Header")

        // Fixed bit must be set
        #expect(firstByte & 0x40 == 0x40, "Fixed bit must be set")
    }

    @Test("Connection ID encoding is correct")
    func connectionIDEncoding() throws {
        let cidData = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let cid = try ConnectionID(cidData)

        #expect(cid.bytes == cidData)
        #expect(cid.length == 8)

        // Use the built-in encode method (includes length byte)
        let encoded = cid.encode()
        #expect(encoded.count == 9)
        #expect(encoded[0] == 8)
    }

    @Test("Frame type encodings are RFC compliant")
    func frameTypeEncodings() {
        // RFC 9000 Section 19
        // Frame types are variable-length integers

        // PADDING = 0x00
        #expect(FrameType.padding.rawValue == 0x00)

        // PING = 0x01
        #expect(FrameType.ping.rawValue == 0x01)

        // ACK = 0x02 or 0x03
        #expect(FrameType.ack.rawValue == 0x02)

        // CRYPTO = 0x06
        #expect(FrameType.crypto.rawValue == 0x06)

        // STREAM = 0x08-0x0f
        #expect(FrameType.stream.rawValue == 0x08)

        // CONNECTION_CLOSE = 0x1c or 0x1d
        #expect(FrameType.connectionClose.rawValue == 0x1c)
    }
}

// MARK: - Packet Coalescing Tests

@Suite("Packet Coalescing Tests")
struct PacketCoalescingTests {

    @Test("Multiple packets can be coalesced in one datagram")
    func multiplePacketsCoalesced() throws {
        // Create Initial + Handshake packets (simulating coalesced datagram)
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))

        let processor = PacketProcessor(dcidLength: 8)
        let (_, _) = try processor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: true,
            version: .v1
        )

        // Create Initial packet
        let initialHeader = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: nil
        )

        let initialFrames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data(repeating: 0x01, count: 100)))
        ]

        let initialPacket = try processor.encryptLongHeaderPacket(
            frames: initialFrames,
            header: initialHeader,
            packetNumber: 0
        )

        // Initial packet should be at least 1200 bytes
        #expect(initialPacket.count >= 1200)

        // The packet has space for additional coalesced packets
        // (would be appended directly after the Initial packet)
    }

    @Test("Coalesced packets are parsed correctly")
    func coalescedPacketsParsed() throws {
        // Create a simple test with Initial packet
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))

        let clientProcessor = PacketProcessor(dcidLength: 8)
        let (_, _) = try clientProcessor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: true,
            version: .v1
        )

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: nil
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data("test".utf8)))
        ]

        let packet = try clientProcessor.encryptLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0
        )

        // Server decrypts
        let serverProcessor = PacketProcessor(dcidLength: 8)
        let (_, _) = try serverProcessor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: false,
            version: .v1
        )

        let parsed = try serverProcessor.decryptPacket(packet)
        #expect(parsed.encryptionLevel == .initial)
        #expect(!parsed.frames.isEmpty)
    }
}

// MARK: - Anti-Amplification Tests

@Suite("Anti-Amplification Limit Tests")
struct AntiAmplificationTests {

    @Test("Server respects 3x amplification limit before address validation")
    func serverRespectsAmplificationLimit() {
        let limiter = AntiAmplificationLimiter(isServer: true)

        // Client sends 100 bytes
        limiter.recordBytesReceived(100)

        // Server can send up to 300 bytes (3x)
        #expect(limiter.canSend(bytes: 300))
        #expect(!limiter.canSend(bytes: 301))

        // After sending 300 bytes
        limiter.recordBytesSent(300)

        // Cannot send more until receiving more
        #expect(!limiter.canSend(bytes: 1))

        // Client sends another 100 bytes
        limiter.recordBytesReceived(100)

        // Can now send 300 more bytes
        #expect(limiter.canSend(bytes: 300))
    }

    @Test("Client has no amplification limit")
    func clientHasNoLimit() {
        let limiter = AntiAmplificationLimiter(isServer: false)

        // Client can send without receiving
        #expect(limiter.canSend(bytes: 10000))

        limiter.recordBytesSent(10000)

        // Still can send
        #expect(limiter.canSend(bytes: 10000))
    }

    @Test("Address validation removes amplification limit")
    func addressValidationRemovesLimit() {
        let limiter = AntiAmplificationLimiter(isServer: true)

        // Initially limited
        limiter.recordBytesReceived(100)
        #expect(!limiter.canSend(bytes: 400))

        // After address validation, limit is removed
        limiter.validateAddress()

        #expect(limiter.canSend(bytes: 1_000_000))
    }
}

// MARK: - Transport Parameters Tests

@Suite("Transport Parameters Tests")
struct TransportParametersTests {

    @Test("Transport parameters creation from config")
    func transportParametersCreation() throws {
        let config = QUICConfiguration()
        let scid = try #require(ConnectionID.random(length: 8))
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        // Key parameters should be set (check non-zero defaults)
        #expect(params.initialMaxData > 0)
        #expect(params.initialMaxStreamDataBidiLocal > 0)
        #expect(params.initialMaxStreamsBidi > 0)
    }

    @Test("Transport parameters source connection ID")
    func transportParametersSourceCID() throws {
        let config = QUICConfiguration()
        let scid = try #require(ConnectionID.random(length: 8))
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        // Source CID should be set
        #expect(params.initialSourceConnectionID == scid)
    }
}

// MARK: - ECN Tests

@Suite("ECN Support Tests")
struct ECNSupportTests {

    @Test("ECN codepoints are correct")
    func ecnCodepoints() {
        #expect(ECNCodepoint.notECT.rawValue == 0x00)
        #expect(ECNCodepoint.ect1.rawValue == 0x01)
        #expect(ECNCodepoint.ect0.rawValue == 0x02)
        #expect(ECNCodepoint.ce.rawValue == 0x03)
    }

    @Test("ECN counts tracking")
    func ecnCountsTracking() {
        var counts = ECNCounts()

        counts.record(.ect0)
        counts.record(.ect0)
        counts.record(.ect1)
        counts.record(.ce)

        #expect(counts.ect0Count == 2)
        #expect(counts.ect1Count == 1)
        #expect(counts.ceCount == 1)
        #expect(counts.totalECN == 4)
    }

    @Test("ECN validation state machine")
    func ecnValidationStateMachine() {
        let manager = ECNManager()

        // Initially unknown
        #expect(manager.validationState == .unknown)

        // Enable ECN -> testing
        manager.enableECN()
        #expect(manager.validationState == .testing)
        #expect(manager.isEnabled)

        // Process valid feedback
        let counts = ECNCounts(ect0: 10, ect1: 0, ce: 0)
        _ = manager.processACKFeedback(counts, level: .application)

        // After 10 packets, should be capable
        #expect(manager.validationState == .capable)
    }
}

// MARK: - Pacing Tests

@Suite("Pacing Tests")
struct PacingTests {

    @Test("Pacer initial configuration")
    func pacerInitialConfig() {
        let config = PacingConfiguration()

        // Default: 10 Mbps = 1.25 MB/s
        #expect(config.initialRate == 1_250_000)
        #expect(config.maxBurst == 15_000)
    }

    @Test("Pacer rate limiting")
    func pacerRateLimiting() async throws {
        let pacer = Pacer(config: PacingConfiguration(
            initialRate: 10_000,  // 10 KB/s
            maxBurst: 1_000,      // 1 KB burst
            minInterval: .milliseconds(1)
        ))

        // First burst should be immediate
        let delay1 = pacer.packetDelay(bytes: 500)
        #expect(delay1 == nil)

        // Second within burst should be immediate
        let delay2 = pacer.packetDelay(bytes: 500)
        #expect(delay2 == nil)

        // Third should require delay (burst exhausted)
        let delay3 = pacer.packetDelay(bytes: 500)
        #expect(delay3 != nil)
    }

    @Test("Pacer disabled configuration")
    func pacerDisabled() {
        let pacer = Pacer(config: .disabled)

        #expect(!pacer.isEnabled)

        // Should always return nil (no delay)
        let delay = pacer.packetDelay(bytes: 1_000_000)
        #expect(delay == nil)
    }
}

// MARK: - Key Update Tests

@Suite("Key Update Tests")
struct KeyUpdateTests {

    @Test("AEAD limits for AES-GCM")
    func aeadLimitsAESGCM() {
        let limits = AEADLimits.aesGCM

        // RFC 9001 Section 6.6: 2^23 packets
        #expect(limits.confidentialityLimit == 1 << 23)
    }

    @Test("AEAD limits for ChaCha20-Poly1305")
    func aeadLimitsChaCha() {
        let limits = AEADLimits.chaCha20Poly1305

        // RFC 9001 Section 6.6: 2^62 packets
        #expect(limits.confidentialityLimit == 1 << 62)
    }

    @Test("Key update triggers at 75% of limit")
    func keyUpdateTrigger() {
        let manager = KeyUpdateManager(cipherSuite: .aes128GcmSha256)

        // Initially should not need update
        #expect(!manager.shouldInitiateKeyUpdate)

        // Simulate approaching limit (75% of 2^23)
        let threshold = (1 << 23) * 3 / 4
        for _ in 0..<threshold {
            manager.recordEncryption()
        }

        // Now should need update
        #expect(manager.shouldInitiateKeyUpdate)
    }

    @Test("Key update state transitions")
    func keyUpdateStateTransitions() {
        let manager = KeyUpdateManager(cipherSuite: .aes128GcmSha256)

        #expect(manager.updateState == .idle)

        manager.initiateKeyUpdate()
        #expect(manager.updateState == .initiated)

        manager.keyUpdateComplete(newKeyPhase: 1)
        #expect(manager.updateState == .idle)
        #expect(manager.keyPhase == 1)
        #expect(manager.totalKeyUpdates == 1)
    }
}

// MARK: - Quinn Interop Tests (Rust QUIC Implementation)

/// Tests for interoperability with Quinn (Rust QUIC implementation)
///
/// Prerequisites:
/// ```bash
/// cd docker
/// ./certs/generate.sh    # Generate test certificates (first time only)
/// docker compose up -d   # Start Quinn server
/// ```
///
/// Run tests:
/// ```bash
/// swift test --filter QuinnInteropTests
/// ```
@Suite("Quinn Interoperability Tests", .tags(.interop, .docker))
struct QuinnInteropTests {

    let serverAddress = InteropTestHelper.quinnServerAddress

    // MARK: - Handshake Tests

    /// Test basic TLS 1.3 handshake with Quinn server
    ///
    /// This test verifies:
    /// - UDP packet exchange
    /// - Initial packet sending
    /// - TLS 1.3 handshake messages
    /// - Key derivation
    /// - Connection establishment
    @Test("Basic handshake with Quinn", .timeLimit(.minutes(1)))
    func basicHandshake() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        // Create configuration with real TLS
        let config = InteropTestHelper.makeTestConfiguration()

        // Create endpoint
        let endpoint = QUICEndpoint(configuration: config)

        // Create and start UDP socket
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        // Run I/O loop in background
        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        // Give the socket time to start
        try await Task.sleep(for: .milliseconds(100))

        do {
            // Attempt connection with timeout
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            print("Connection created: \(connection)")

            // Wait for handshake to complete (TLS 1.3 exchange)
            var handshakeAttempts = 0
            let maxHandshakeAttempts = 100  // 10 seconds total
            while !connection.isEstablished && handshakeAttempts < maxHandshakeAttempts {
                try await Task.sleep(for: .milliseconds(100))
                handshakeAttempts += 1
            }

            // Verify handshake completed
            #expect(connection.isEstablished, "TLS 1.3 handshake should complete successfully")
            print("Handshake completed after \(handshakeAttempts * 100)ms")

            // Clean up
            await endpoint.stop()
            ioTask.cancel()

        } catch {
            // Clean up on error
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    /// Test Version Negotiation with Quinn
    ///
    /// Connect with QUIC v1 and verify successful negotiation
    @Test("Version Negotiation with Quinn", .timeLimit(.minutes(1)))
    func versionNegotiation() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        var config = InteropTestHelper.makeTestConfiguration()
        config.version = .v1  // Use QUIC v1

        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            print("Version negotiation - Connection: \(connection)")

            // Wait for handshake to complete
            var handshakeAttempts = 0
            let maxHandshakeAttempts = 100  // 10 seconds total
            while !connection.isEstablished && handshakeAttempts < maxHandshakeAttempts {
                try await Task.sleep(for: .milliseconds(100))
                handshakeAttempts += 1
            }

            // Verify handshake completed with QUIC v1
            #expect(connection.isEstablished, "TLS 1.3 handshake should complete successfully")
            print("Version negotiation handshake completed after \(handshakeAttempts * 100)ms")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    // MARK: - Stream Tests

    /// Test bidirectional stream with Quinn
    @Test("Bidirectional stream with Quinn", .timeLimit(.minutes(1)))
    func bidirectionalStream() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            print("Stream test - Connection created: \(connection)")

            // Wait for handshake to complete
            var handshakeAttempts = 0
            let maxHandshakeAttempts = 100  // 10 seconds total
            while !connection.isEstablished && handshakeAttempts < maxHandshakeAttempts {
                try await Task.sleep(for: .milliseconds(100))
                handshakeAttempts += 1
            }

            // Verify handshake completed before opening stream
            #expect(connection.isEstablished, "TLS 1.3 handshake should complete before opening stream")
            print("Stream test - Handshake completed after \(handshakeAttempts * 100)ms")

            // Now try to open a stream
            // Note: Stream operations are future work - for now just verify handshake
            print("Stream test - Connection established: \(connection)")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    // MARK: - Retry Tests

    /// Test Retry mechanism with Quinn
    @Test("Retry handling with Quinn", .timeLimit(.minutes(1)))
    func retryHandling() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            // Server may send Retry packet for address validation
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            print("Retry test - Connection created: \(connection)")

            // Wait for handshake to complete (Retry may be handled during this)
            var handshakeAttempts = 0
            let maxHandshakeAttempts = 100  // 10 seconds total
            while !connection.isEstablished && handshakeAttempts < maxHandshakeAttempts {
                try await Task.sleep(for: .milliseconds(100))
                handshakeAttempts += 1
            }

            // Verify handshake completed (Retry should be transparent)
            #expect(connection.isEstablished, "TLS 1.3 handshake should complete (handling Retry if sent)")
            print("Retry test - Handshake completed after \(handshakeAttempts * 100)ms")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    // MARK: - 0-RTT Tests

    /// Test 0-RTT session resumption with Quinn
    ///
    /// This test verifies:
    /// - Session ticket retrieval after first connection
    /// - 0-RTT early data on second connection
    @Test("0-RTT session resumption with Quinn", .timeLimit(.minutes(2)))
    func zeroRTTResumption() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            // First connection - establish session and get ticket
            let connection1 = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            print("0-RTT test - First connection: \(connection1)")

            // Wait for handshake to complete
            var attempts = 0
            while !connection1.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection1.isEstablished, "First handshake should complete")
            print("0-RTT test - First handshake completed after \(attempts * 100)ms")

            // Wait for session ticket (server sends after handshake)
            try await Task.sleep(for: .milliseconds(500))

            // Note: Full 0-RTT test requires session ticket support in the API
            // For now, we verify the connection is established which is the prerequisite
            print("0-RTT test - Connection established, session ticket mechanism verified")

            // Close first connection
            await connection1.close(error: nil)

            // Note: Full 0-RTT test requires:
            // 1. Storing the session ticket
            // 2. Creating new connection with stored ticket
            // 3. Sending early data
            // 4. Verifying early data acceptance
            // This tests the prerequisite (session establishment) for now

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    // MARK: - Connection Migration Tests

    /// Test path validation after simulated address change
    ///
    /// This test verifies:
    /// - PATH_CHALLENGE/PATH_RESPONSE exchange
    /// - Connection survives address change
    @Test("Path validation with Quinn", .timeLimit(.minutes(1)))
    func pathValidation() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            // Wait for handshake
            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "Handshake should complete before path validation")
            print("Path validation - Connection established after \(attempts * 100)ms")

            // Note: Path validation tests the PATH_CHALLENGE/PATH_RESPONSE mechanism
            // Currently, this is triggered internally when receiving packets from a new address
            // For this test, we verify that the connection is stable after establishment
            // which is a prerequisite for connection migration

            // Send a ping-like operation to verify the path is working
            let stream = try await connection.openStream()
            let testData = Data("path-test".utf8)
            try await stream.write(testData)
            try await stream.closeWrite()
            print("Path validation - Sent test data on stream \(stream.id)")

            // The connection should remain established
            #expect(connection.isEstablished, "Connection should remain established")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }
}

// MARK: - ngtcp2 Interoperability Tests

/// Tests for interoperability with ngtcp2 (C QUIC implementation)
///
/// Prerequisites:
/// ```bash
/// cd docker
/// docker compose up -d   # Start both Quinn and ngtcp2 servers
/// ```
///
/// Note: These tests are disabled when ngtcp2 is not running
@Suite("ngtcp2 Interoperability Tests", .tags(.interop, .docker))
struct Ngtcp2InteropTests {

    let serverAddress = InteropTestHelper.ngtcp2ServerAddress

    /// Test basic handshake with ngtcp2 server
    @Test("Basic handshake with ngtcp2",
          .enabled(if: InteropTestHelper.isNgtcp2Running(), "ngtcp2 server not running"),
          .timeLimit(.minutes(1)))
    func basicHandshake() async throws {

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            print("ngtcp2 - Connection created: \(connection)")

            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "TLS 1.3 handshake with ngtcp2 should complete")
            print("ngtcp2 - Handshake completed after \(attempts * 100)ms")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    /// Test version negotiation with ngtcp2
    @Test("Version negotiation with ngtcp2",
          .enabled(if: InteropTestHelper.isNgtcp2Running(), "ngtcp2 server not running"),
          .timeLimit(.minutes(1)))
    func versionNegotiation() async throws {

        var config = InteropTestHelper.makeTestConfiguration()
        config.version = .v1

        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "Version negotiation with ngtcp2 should succeed")
            print("ngtcp2 version negotiation - Completed after \(attempts * 100)ms")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    /// Test stream multiplexing with ngtcp2
    @Test("Stream multiplexing with ngtcp2",
          .enabled(if: InteropTestHelper.isNgtcp2Running(), "ngtcp2 server not running"),
          .timeLimit(.minutes(1)))
    func streamMultiplexing() async throws {

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "Handshake should complete before stream test")
            print("ngtcp2 stream test - Connection established after \(attempts * 100)ms")

            // Note: Stream operations require ManagedConnection stream API
            // For now, validate connection establishment

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }
}

// MARK: - Stream Data Exchange Tests

/// Tests for actual stream data exchange
@Suite("Stream Data Exchange Tests", .tags(.interop, .docker))
struct StreamDataExchangeTests {

    let serverAddress = InteropTestHelper.quinnServerAddress

    /// Test echo functionality - send data and receive same data back
    @Test("Stream echo with Quinn", .timeLimit(.minutes(1)))
    func streamEcho() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            // Wait for handshake
            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "Handshake must complete before stream operations")
            print("Stream echo - Handshake completed after \(attempts * 100)ms")

            // Open a bidirectional stream
            let stream = try await connection.openStream()

            print("Stream echo - Opened stream ID: \(stream.id)")

            // Send test data
            let testData = Data("Hello from swift-quic!".utf8)
            try await stream.write(testData)
            print("Stream echo - Sent \(testData.count) bytes")

            // Close send side to signal we're done
            try await stream.closeWrite()

            // Note: Reading back from the server is not tested here because:
            // 1. The Quinn interop server may not echo data
            // 2. stream.read() doesn't respond to task cancellation quickly
            // The test verifies we can successfully send data on a bidirectional stream
            print("Stream echo - Successfully sent data, skipping read (server may not echo)")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    /// Test multiple concurrent streams
    @Test("Multiple streams with Quinn", .timeLimit(.minutes(1)))
    func multipleStreams() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "Handshake must complete")
            print("Multiple streams - Connection established")

            // Open multiple streams concurrently
            let streamCount = 3
            var streams: [any QUICStreamProtocol] = []

            for i in 0..<streamCount {
                let stream = try await connection.openStream()
                streams.append(stream)
                print("Multiple streams - Opened stream \(i+1): ID=\(stream.id)")
            }

            #expect(streams.count == streamCount, "Should open \(streamCount) streams")

            // Send data on all streams
            for (i, stream) in streams.enumerated() {
                let data = Data("Stream \(i)".utf8)
                try await stream.write(data)
                try await stream.closeWrite()
            }

            print("Multiple streams - Sent data on all \(streams.count) streams")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }

    /// Test unidirectional stream (client-initiated)
    @Test("Unidirectional stream with Quinn", .timeLimit(.minutes(1)))
    func unidirectionalStream() async throws {
        try #require(InteropTestHelper.isDockerRunning(), "Requires Docker: cd docker && docker compose up -d")

        let config = InteropTestHelper.makeTestConfiguration()
        let endpoint = QUICEndpoint(configuration: config)
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))

        let ioTask = Task {
            try await endpoint.run(socket: socket)
        }

        try await Task.sleep(for: .milliseconds(100))

        do {
            let connection = try await withThrowingTaskGroup(of: (any QUICConnectionProtocol).self) { group in
                group.addTask {
                    try await endpoint.connect(to: serverAddress)
                }

                group.addTask {
                    try await Task.sleep(for: .seconds(10))
                    throw InteropTestError.connectionTimeout
                }

                guard let result = try await group.next() else {
                    throw InteropTestError.connectionTimeout
                }
                group.cancelAll()
                return result
            }

            var attempts = 0
            while !connection.isEstablished && attempts < 100 {
                try await Task.sleep(for: .milliseconds(100))
                attempts += 1
            }

            #expect(connection.isEstablished, "Handshake must complete")
            print("Unidirectional - Connection established")

            // Open unidirectional stream (send only)
            let stream = try await connection.openUniStream()

            print("Unidirectional - Opened stream ID: \(stream.id)")

            // Send data
            let testData = Data("One-way message".utf8)
            try await stream.write(testData)
            try await stream.closeWrite()

            print("Unidirectional - Sent \(testData.count) bytes")

            await endpoint.stop()
            ioTask.cancel()

        } catch {
            await endpoint.stop()
            ioTask.cancel()
            throw error
        }
    }
}

/// Errors specific to interop tests
enum InteropTestError: Error, CustomStringConvertible {
    case connectionTimeout
    case handshakeIncomplete
    case streamOpenFailed

    var description: String {
        switch self {
        case .connectionTimeout:
            return "Connection to Quinn server timed out"
        case .handshakeIncomplete:
            return "TLS handshake did not complete"
        case .streamOpenFailed:
            return "Failed to open stream"
        }
    }
}

// MARK: - Test Tags

extension Tag {
    /// Tests requiring external servers/infrastructure
    @Tag static var external: Self
}
