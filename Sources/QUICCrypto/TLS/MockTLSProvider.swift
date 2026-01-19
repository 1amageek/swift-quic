/// Mock TLS 1.3 Provider for Testing
///
/// A mock implementation of TLS13Provider that simulates
/// TLS handshake for testing QUIC without a real TLS stack.
///
/// - Warning: This provider is only available in DEBUG builds.
///   It provides no security and must never be used in production.

import Foundation
import Crypto
import Synchronization
import QUICCore

#if DEBUG

// MARK: - Mock TLS Provider

/// Mock TLS provider for testing QUIC handshake flow
///
/// This mock simulates the TLS 1.3 handshake without actual cryptographic
/// operations. It generates deterministic secrets for testing and allows
/// configuration of various scenarios.
///
/// - Warning: This class is only available in DEBUG builds.
///   Never use MockTLSProvider in production code.
public final class MockTLSProvider: TLS13Provider, Sendable {
    /// Internal state
    private let state: Mutex<MockTLSState>

    /// Configuration
    private let configuration: TLSConfiguration

    /// Whether to simulate handshake completion immediately
    private let immediateCompletion: Bool

    /// Simulated handshake delay (for async testing)
    private let simulatedDelay: Duration?

    // MARK: - Initialization

    /// Creates a mock TLS provider
    /// - Parameters:
    ///   - configuration: TLS configuration
    ///   - immediateCompletion: If true, handshake completes in one round trip
    ///   - simulatedDelay: Optional delay to simulate network latency
    public init(
        configuration: TLSConfiguration = TLSConfiguration(),
        immediateCompletion: Bool = true,
        simulatedDelay: Duration? = nil
    ) {
        self.configuration = configuration
        self.immediateCompletion = immediateCompletion
        self.simulatedDelay = simulatedDelay
        self.state = Mutex(MockTLSState())
    }

    // MARK: - TLS13Provider Protocol

    public func startHandshake(isClient: Bool) async throws -> [TLSOutput] {
        if let delay = simulatedDelay {
            try await Task.sleep(for: delay)
        }

        // Get local transport params and forceComplete status before acquiring the lock
        let (localParams, wasForceCompleted) = state.withLock {
            ($0.localTransportParameters, $0.handshakeComplete)
        }

        return state.withLock { state in
            state.isClient = isClient
            state.handshakeStarted = true

            var outputs: [TLSOutput] = []

            // If forceComplete() was called before startHandshake(), return all outputs
            // needed to complete the handshake immediately
            if wasForceCompleted {
                // Derive keys
                let handshakeClientSecret = generateDeterministicSecret(label: "client_hs")
                let handshakeServerSecret = generateDeterministicSecret(label: "server_hs")
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .handshake,
                    clientSecret: handshakeClientSecret,
                    serverSecret: handshakeServerSecret
                )))

                let appClientSecret = generateDeterministicSecret(label: "client_app")
                let appServerSecret = generateDeterministicSecret(label: "server_app")
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: appClientSecret,
                    serverSecret: appServerSecret
                )))

                // Set mock peer transport parameters
                state.peerTransportParameters = generateMockPeerTransportParameters()
                state.negotiatedALPN = configuration.alpnProtocols.first

                outputs.append(.handshakeComplete(HandshakeCompleteInfo(
                    alpn: state.negotiatedALPN,
                    zeroRTTAccepted: false,
                    resumptionTicket: nil
                )))

                return outputs
            }

            if isClient {
                // Client: Generate ClientHello (pass params to avoid nested lock)
                let clientHello = generateMockClientHello(localParams: localParams)
                outputs.append(.handshakeData(clientHello, level: .initial))
            }

            return outputs
        }
    }

    public func processHandshakeData(_ data: Data, at level: EncryptionLevel) async throws -> [TLSOutput] {
        if let delay = simulatedDelay {
            try await Task.sleep(for: delay)
        }

        return state.withLock { state in
            var outputs: [TLSOutput] = []

            if state.isClient {
                // Client processing server messages
                outputs.append(contentsOf: processAsClient(&state, data: data, level: level))
            } else {
                // Server processing client messages
                outputs.append(contentsOf: processAsServer(&state, data: data, level: level))
            }

            return outputs
        }
    }

    public func getLocalTransportParameters() -> Data {
        state.withLock { state in
            state.localTransportParameters ?? Data()
        }
    }

    public func setLocalTransportParameters(_ params: Data) throws {
        state.withLock { state in
            state.localTransportParameters = params
        }
    }

    public func getPeerTransportParameters() -> Data? {
        state.withLock { state in
            state.peerTransportParameters
        }
    }

    public var isHandshakeComplete: Bool {
        state.withLock { $0.handshakeComplete }
    }

    public var isClient: Bool {
        state.withLock { $0.isClient }
    }

    public var negotiatedALPN: String? {
        state.withLock { $0.negotiatedALPN }
    }

    public func configureResumption(ticket: SessionTicketData, attemptEarlyData: Bool) throws {
        state.withLock { state in
            state.resumptionTicket = ticket
            state.attemptEarlyData = attemptEarlyData
        }
    }

    public var is0RTTAccepted: Bool {
        state.withLock { $0.is0RTTAccepted }
    }

    public var is0RTTAttempted: Bool {
        state.withLock { $0.is0RTTAttempted }
    }

    public func requestKeyUpdate() async throws -> [TLSOutput] {
        state.withLock { state in
            state.keyUpdateCount += 1

            // Generate new application secrets
            let newClientSecret = generateDeterministicSecret(
                label: "client_app_\(state.keyUpdateCount)"
            )
            let newServerSecret = generateDeterministicSecret(
                label: "server_app_\(state.keyUpdateCount)"
            )

            return [
                .keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: newClientSecret,
                    serverSecret: newServerSecret
                ))
            ]
        }
    }

    public func exportKeyingMaterial(
        label: String,
        context: Data?,
        length: Int
    ) throws -> Data {
        // Generate deterministic keying material based on label
        let seed = label + (context.map { $0.base64EncodedString() } ?? "")
        return generateDeterministicData(seed: seed, length: length)
    }

    // MARK: - Mock Specific Methods

    /// Sets peer transport parameters (for testing)
    public func setPeerTransportParameters(_ params: Data) {
        state.withLock { state in
            state.peerTransportParameters = params
        }
    }

    /// Forces handshake completion (for testing)
    ///
    /// Sets the handshake as complete and generates proper peer transport parameters
    /// using RFC 9000 compliant encoding. This ensures that:
    /// 1. `isHandshakeComplete` returns true
    /// 2. `getPeerTransportParameters()` returns valid encoded parameters
    /// 3. Stream limits are properly configured (initialMaxStreamsBidi = 100, etc.)
    public func forceComplete() {
        state.withLock { state in
            state.handshakeComplete = true
            // Set peer transport parameters with RFC-compliant encoding
            // This is critical for stream opening to work (stream limit checks)
            if state.peerTransportParameters == nil {
                state.peerTransportParameters = generateMockPeerTransportParameters()
            }
            state.negotiatedALPN = configuration.alpnProtocols.first
        }
    }

    /// Resets the mock state
    public func reset() {
        state.withLock { state in
            state = MockTLSState()
        }
    }

    // MARK: - Private Helpers

    private func processAsClient(
        _ state: inout MockTLSState,
        data: Data,
        level: EncryptionLevel
    ) -> [TLSOutput] {
        var outputs: [TLSOutput] = []

        switch level {
        case .initial:
            // Received ServerHello - derive handshake keys
            let handshakeClientSecret = generateDeterministicSecret(label: "client_hs")
            let handshakeServerSecret = generateDeterministicSecret(label: "server_hs")

            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .handshake,
                clientSecret: handshakeClientSecret,
                serverSecret: handshakeServerSecret
            )))

            state.handshakeKeysAvailable = true

        case .handshake:
            // Received EncryptedExtensions, Certificate, etc.
            // Extract transport parameters from "server" data
            state.peerTransportParameters = extractMockTransportParameters(from: data)

            if immediateCompletion {
                // Generate Finished and application keys
                let clientFinished = generateMockFinished()
                outputs.append(.handshakeData(clientFinished, level: .handshake))

                let appClientSecret = generateDeterministicSecret(label: "client_app")
                let appServerSecret = generateDeterministicSecret(label: "server_app")

                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: appClientSecret,
                    serverSecret: appServerSecret
                )))

                state.handshakeComplete = true
                state.negotiatedALPN = configuration.alpnProtocols.first

                outputs.append(.handshakeComplete(HandshakeCompleteInfo(
                    alpn: state.negotiatedALPN,
                    zeroRTTAccepted: false,
                    resumptionTicket: nil
                )))
            }

        case .application:
            // Post-handshake messages (NewSessionTicket, etc.)
            break

        default:
            break
        }

        return outputs
    }

    private func processAsServer(
        _ state: inout MockTLSState,
        data: Data,
        level: EncryptionLevel
    ) -> [TLSOutput] {
        var outputs: [TLSOutput] = []

        switch level {
        case .initial:
            // Received ClientHello
            state.peerTransportParameters = extractMockTransportParameters(from: data)

            // Send ServerHello
            let serverHello = generateMockServerHello()
            outputs.append(.handshakeData(serverHello, level: .initial))

            // Derive handshake keys
            let handshakeClientSecret = generateDeterministicSecret(label: "client_hs")
            let handshakeServerSecret = generateDeterministicSecret(label: "server_hs")

            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .handshake,
                clientSecret: handshakeClientSecret,
                serverSecret: handshakeServerSecret
            )))

            state.handshakeKeysAvailable = true

            // Send EncryptedExtensions, Certificate, CertificateVerify, Finished
            let handshakeMessages = generateMockServerHandshakeMessages(localParams: state.localTransportParameters)
            outputs.append(.handshakeData(handshakeMessages, level: .handshake))

            if immediateCompletion {
                // Derive application keys
                let appClientSecret = generateDeterministicSecret(label: "client_app")
                let appServerSecret = generateDeterministicSecret(label: "server_app")

                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: appClientSecret,
                    serverSecret: appServerSecret
                )))
            }

        case .handshake:
            // Received client Finished
            if !state.handshakeComplete {
                state.handshakeComplete = true
                state.negotiatedALPN = configuration.alpnProtocols.first

                if !immediateCompletion {
                    let appClientSecret = generateDeterministicSecret(label: "client_app")
                    let appServerSecret = generateDeterministicSecret(label: "server_app")

                    outputs.append(.keysAvailable(KeysAvailableInfo(
                        level: .application,
                        clientSecret: appClientSecret,
                        serverSecret: appServerSecret
                    )))
                }

                outputs.append(.handshakeComplete(HandshakeCompleteInfo(
                    alpn: state.negotiatedALPN,
                    zeroRTTAccepted: false,
                    resumptionTicket: nil
                )))
            }

        case .application:
            break

        default:
            break
        }

        return outputs
    }

    private func generateMockClientHello(localParams: Data?) -> Data {
        // Mock ClientHello with marker
        var data = Data("MOCK_CLIENT_HELLO".utf8)
        if let params = localParams {
            data.append(params)
        }
        return data
    }

    private func generateMockServerHello() -> Data {
        Data("MOCK_SERVER_HELLO".utf8)
    }

    private func generateMockServerHandshakeMessages(localParams: Data?) -> Data {
        var data = Data("MOCK_ENCRYPTED_EXTENSIONS".utf8)
        if let params = localParams {
            data.append(params)
        }
        data.append(Data("MOCK_CERTIFICATE".utf8))
        data.append(Data("MOCK_CERT_VERIFY".utf8))
        data.append(Data("MOCK_FINISHED".utf8))
        return data
    }

    private func generateMockFinished() -> Data {
        Data("MOCK_CLIENT_FINISHED".utf8)
    }

    private func extractMockTransportParameters(from data: Data) -> Data {
        // In a real scenario, parse from TLS extension
        // For mock, just return any embedded parameters
        if data.count > 20 {
            return Data(data.suffix(from: 17))  // Skip mock header
        }
        return Data()
    }

    private func generateMockPeerTransportParameters() -> Data {
        // Generate mock peer transport parameters with RFC 9000 compliant encoding
        // Uses TransportParameterCodec for proper wire format that can be decoded
        // by ManagedConnection when processing handshake completion
        let params = TransportParameters()  // Uses default values with stream limits
        return TransportParameterCodec.encode(params)
    }

    private func generateDeterministicSecret(label: String) -> SymmetricKey {
        let data = generateDeterministicData(seed: label, length: 32)
        return SymmetricKey(data: data)
    }

    private func generateDeterministicData(seed: String, length: Int) -> Data {
        // Generate deterministic bytes from seed for reproducible tests
        var result = Data(count: length)
        let seedData = Data(seed.utf8)
        for i in 0..<length {
            result[i] = seedData[i % seedData.count] ^ UInt8(i & 0xFF)
        }
        return result
    }
}

// MARK: - Mock State

/// Internal state for MockTLSProvider
private struct MockTLSState: Sendable {
    var isClient: Bool = true
    var handshakeStarted: Bool = false
    var handshakeKeysAvailable: Bool = false
    var handshakeComplete: Bool = false
    var negotiatedALPN: String? = nil
    var localTransportParameters: Data? = nil
    var peerTransportParameters: Data? = nil
    var keyUpdateCount: Int = 0

    // 0-RTT state
    var resumptionTicket: SessionTicketData? = nil
    var attemptEarlyData: Bool = false
    var is0RTTAttempted: Bool = false
    var is0RTTAccepted: Bool = false
}

#else

// MARK: - Release Build Stub

/// MockTLSProvider stub for release builds
///
/// This stub exists only to provide compile-time errors if testing mode
/// is accidentally used in release builds. All methods will cause a
/// fatal error if somehow called.
///
/// - Warning: This type should never be instantiated in release builds.
public final class MockTLSProvider: TLS13Provider, Sendable {
    public init(
        configuration: TLSConfiguration = TLSConfiguration(),
        immediateCompletion: Bool = true,
        simulatedDelay: Duration? = nil
    ) {
        fatalError("MockTLSProvider is not available in release builds. Configure a real TLS provider using QUICConfiguration.production() or QUICConfiguration.development().")
    }

    public func startHandshake(isClient: Bool) async throws -> [TLSOutput] {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func processHandshakeData(_ data: Data, at level: EncryptionLevel) async throws -> [TLSOutput] {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func getLocalTransportParameters() -> Data {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func setLocalTransportParameters(_ params: Data) throws {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func getPeerTransportParameters() -> Data? {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public var isHandshakeComplete: Bool {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public var isClient: Bool {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public var negotiatedALPN: String? {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func configureResumption(ticket: SessionTicketData, attemptEarlyData: Bool) throws {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public var is0RTTAccepted: Bool {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public var is0RTTAttempted: Bool {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func requestKeyUpdate() async throws -> [TLSOutput] {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func exportKeyingMaterial(label: String, context: Data?, length: Int) throws -> Data {
        fatalError("MockTLSProvider is not available in release builds")
    }

    // Mock-specific methods that will fail in release builds
    public func setPeerTransportParameters(_ params: Data) {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func forceComplete() {
        fatalError("MockTLSProvider is not available in release builds")
    }

    public func reset() {
        fatalError("MockTLSProvider is not available in release builds")
    }
}

#endif
