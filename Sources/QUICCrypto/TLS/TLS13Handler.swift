/// TLS 1.3 Handler - Main Implementation of TLS13Provider
///
/// Implements the TLS13Provider protocol using pure Swift and swift-crypto.
/// Designed specifically for QUIC (no TLS record layer).

import Foundation
import Crypto
import Synchronization
import QUICCore

// MARK: - TLS 1.3 Handler

/// Pure Swift TLS 1.3 implementation for QUIC
public final class TLS13Handler: TLS13Provider, Sendable {

    /// Maximum size for handshake message buffers (64KB per level)
    private static let maxBufferSize = 65536

    private let state = Mutex<HandlerState>(HandlerState())
    private let configuration: TLSConfiguration

    private struct HandlerState: Sendable {
        var isClientMode: Bool = true
        var clientStateMachine: ClientStateMachine?
        var serverStateMachine: ServerStateMachine?
        var localTransportParams: Data?
        var peerTransportParams: Data?
        var negotiatedALPN: String?
        var handshakeComplete: Bool = false

        // Buffer for partial message reassembly (per encryption level)
        var messageBuffers: [EncryptionLevel: Data] = [:]

        // Application secrets for key update
        var clientApplicationSecret: SymmetricKey?
        var serverApplicationSecret: SymmetricKey?
        var keySchedule: TLSKeySchedule = TLSKeySchedule()

        // Exporter master secret (RFC 8446 Section 7.5)
        var exporterMasterSecret: SymmetricKey?

        // Key phase counter (number of key updates performed)
        var keyPhase: UInt8 = 0
    }

    // MARK: - Initialization

    public init(configuration: TLSConfiguration = TLSConfiguration()) {
        self.configuration = configuration
    }

    // MARK: - TLS13Provider Protocol

    public func startHandshake(isClient: Bool) async throws -> [TLSOutput] {
        return try state.withLock { state in
            state.isClientMode = isClient

            if isClient {
                let clientMachine = ClientStateMachine()
                state.clientStateMachine = clientMachine

                let (clientHello, outputs) = try clientMachine.startHandshake(
                    configuration: configuration,
                    transportParameters: state.localTransportParams ?? Data()
                )

                var result = outputs
                result.insert(.handshakeData(clientHello, level: .initial), at: 0)
                return result
            } else {
                let serverMachine = ServerStateMachine(configuration: configuration)
                state.serverStateMachine = serverMachine
                return []  // Server waits for ClientHello
            }
        }
    }

    public func processHandshakeData(_ data: Data, at level: EncryptionLevel) async throws -> [TLSOutput] {
        return try state.withLock { state in
            // Append to level-specific buffer
            var buffer = state.messageBuffers[level] ?? Data()
            buffer.append(data)

            // Check buffer size limit to prevent DoS
            guard buffer.count <= Self.maxBufferSize else {
                throw TLSError.internalError("Handshake buffer exceeded maximum size")
            }

            var outputs: [TLSOutput] = []

            // Process complete messages from buffer
            while buffer.count >= 4 {
                // Parse handshake header
                let (messageType, contentLength) = try HandshakeCodec.decodeHeader(from: buffer)
                let totalLength = 4 + contentLength

                guard buffer.count >= totalLength else {
                    // Need more data
                    if outputs.isEmpty {
                        outputs.append(.needMoreData)
                    }
                    break
                }

                // Extract message content
                let content = buffer.subdata(in: 4..<totalLength)

                // Remove from buffer
                buffer = Data(buffer.dropFirst(totalLength))

                // Process the message
                let messageOutputs = try processMessage(
                    type: messageType,
                    content: content,
                    level: level,
                    state: &state
                )
                outputs.append(contentsOf: messageOutputs)
            }

            // Store updated buffer
            state.messageBuffers[level] = buffer

            return outputs
        }
    }

    public func getLocalTransportParameters() -> Data {
        state.withLock { $0.localTransportParams ?? Data() }
    }

    public func setLocalTransportParameters(_ params: Data) throws {
        state.withLock { $0.localTransportParams = params }
    }

    public func getPeerTransportParameters() -> Data? {
        state.withLock { $0.peerTransportParams }
    }

    public var isHandshakeComplete: Bool {
        state.withLock { $0.handshakeComplete }
    }

    public var isClient: Bool {
        state.withLock { $0.isClientMode }
    }

    public var negotiatedALPN: String? {
        state.withLock { $0.negotiatedALPN }
    }

    public func requestKeyUpdate() async throws -> [TLSOutput] {
        // Key update implementation (RFC 9001 Section 6 for QUIC)
        return try state.withLock { state in
            guard state.handshakeComplete else {
                throw TLSError.unexpectedMessage("Cannot request key update before handshake complete")
            }

            guard let currentClientSecret = state.clientApplicationSecret,
                  let currentServerSecret = state.serverApplicationSecret else {
                throw TLSError.internalError("Application secrets not available for key update")
            }

            // Derive next application traffic secrets
            let nextClientSecret = state.keySchedule.nextApplicationSecret(
                from: currentClientSecret
            )
            let nextServerSecret = state.keySchedule.nextApplicationSecret(
                from: currentServerSecret
            )

            // Update stored secrets
            state.clientApplicationSecret = nextClientSecret
            state.serverApplicationSecret = nextServerSecret
            state.keyPhase = (state.keyPhase + 1) % 2  // Toggle key phase bit

            return [
                .keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: nextClientSecret,
                    serverSecret: nextServerSecret
                ))
            ]
        }
    }

    /// Current key phase (0 or 1, toggles with each key update)
    public var keyPhase: UInt8 {
        state.withLock { $0.keyPhase }
    }

    public func exportKeyingMaterial(
        label: String,
        context: Data?,
        length: Int
    ) throws -> Data {
        // RFC 8446 Section 7.5: Exporters
        // 1. Derive-Secret(exporter_master_secret, label, "") = derived_secret
        // 2. HKDF-Expand-Label(derived_secret, "exporter", Hash(context), length)
        try state.withLock { state in
            guard state.handshakeComplete else {
                throw TLSError.unexpectedMessage("Cannot export keying material before handshake complete")
            }

            guard let exporterMasterSecret = state.exporterMasterSecret else {
                throw TLSError.internalError("Exporter master secret not available")
            }

            // Step 1: Derive-Secret(exporter_master_secret, label, "")
            // = HKDF-Expand-Label(exporter_master_secret, label, Hash(""), Hash.length)
            let emptyHash = Data(SHA256.hash(data: Data()))
            let derivedSecret = hkdfExpandLabel(
                secret: exporterMasterSecret,
                label: label,
                context: emptyHash,
                length: 32
            )

            // Step 2: HKDF-Expand-Label(derived_secret, "exporter", Hash(context), length)
            let contextHash = context.map { Data(SHA256.hash(data: $0)) } ?? emptyHash
            let output = hkdfExpandLabel(
                secret: SymmetricKey(data: derivedSecret),
                label: "exporter",
                context: contextHash,
                length: length
            )

            return output
        }
    }

    /// HKDF-Expand-Label helper
    private func hkdfExpandLabel(
        secret: SymmetricKey,
        label: String,
        context: Data,
        length: Int
    ) -> Data {
        let fullLabel = "tls13 " + label
        let labelBytes = Data(fullLabel.utf8)

        var hkdfLabel = Data()
        hkdfLabel.append(UInt8(length >> 8))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(labelBytes.count))
        hkdfLabel.append(labelBytes)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)

        let output = HKDF<SHA256>.expand(
            pseudoRandomKey: secret,
            info: hkdfLabel,
            outputByteCount: length
        )

        return output.withUnsafeBytes { Data($0) }
    }

    // MARK: - Private Helpers

    /// Validates that a handshake message is received at the correct encryption level
    /// per RFC 9001 Section 4.2
    private func validateEncryptionLevel(
        type: HandshakeType,
        level: EncryptionLevel,
        isClient: Bool
    ) throws {
        let expectedLevel: EncryptionLevel
        switch type {
        case .clientHello, .serverHello:
            expectedLevel = .initial
        case .encryptedExtensions, .certificate, .certificateVerify, .finished:
            expectedLevel = .handshake
        case .keyUpdate, .newSessionTicket:
            expectedLevel = .application
        default:
            // Unknown types are handled elsewhere
            return
        }

        guard level == expectedLevel else {
            throw TLSError.unexpectedMessage(
                "Message \(type) received at \(level) level, expected \(expectedLevel)"
            )
        }
    }

    private func processMessage(
        type: HandshakeType,
        content: Data,
        level: EncryptionLevel,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        // Validate encryption level per RFC 9001
        try validateEncryptionLevel(type: type, level: level, isClient: state.isClientMode)

        if state.isClientMode {
            return try processClientMessage(type: type, content: content, level: level, state: &state)
        } else {
            return try processServerMessage(type: type, content: content, level: level, state: &state)
        }
    }

    private func processClientMessage(
        type: HandshakeType,
        content: Data,
        level: EncryptionLevel,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        guard let clientMachine = state.clientStateMachine else {
            throw TLSError.internalError("Client state machine not initialized")
        }

        var outputs: [TLSOutput] = []

        switch type {
        case .serverHello:
            outputs = try clientMachine.processServerHello(content)

        case .encryptedExtensions:
            outputs = try clientMachine.processEncryptedExtensions(content)
            // Extract peer transport params
            if let params = clientMachine.peerTransportParameters {
                state.peerTransportParams = params
            }

        case .certificate:
            outputs = try clientMachine.processCertificate(content)

        case .certificateVerify:
            outputs = try clientMachine.processCertificateVerify(content)

        case .finished:
            let (finishedOutputs, clientFinished) = try clientMachine.processServerFinished(content)
            outputs = finishedOutputs

            // Insert client Finished data
            outputs.insert(.handshakeData(clientFinished, level: .handshake), at: 0)

            // Extract application secrets from outputs for key update support
            for output in finishedOutputs {
                if case .keysAvailable(let info) = output, info.level == .application {
                    state.clientApplicationSecret = info.clientSecret
                    state.serverApplicationSecret = info.serverSecret
                }
            }

            // Extract exporter master secret
            state.exporterMasterSecret = clientMachine.exporterMasterSecret

            // Update state
            state.negotiatedALPN = clientMachine.negotiatedALPN
            state.handshakeComplete = true

        default:
            throw TLSError.unexpectedMessage("Unexpected message type \(type) for client")
        }

        return outputs
    }

    private func processServerMessage(
        type: HandshakeType,
        content: Data,
        level: EncryptionLevel,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        guard let serverMachine = state.serverStateMachine else {
            throw TLSError.internalError("Server state machine not initialized")
        }

        var outputs: [TLSOutput] = []

        switch type {
        case .clientHello:
            let (response, clientHelloOutputs) = try serverMachine.processClientHello(
                content,
                transportParameters: state.localTransportParams ?? Data()
            )
            outputs = clientHelloOutputs

            // Extract peer transport params
            if let params = serverMachine.peerTransportParameters {
                state.peerTransportParams = params
            }

            // Extract application secrets from outputs for key update support
            for output in clientHelloOutputs {
                if case .keysAvailable(let info) = output, info.level == .application {
                    state.clientApplicationSecret = info.clientSecret
                    state.serverApplicationSecret = info.serverSecret
                }
            }

            // Extract exporter master secret
            state.exporterMasterSecret = serverMachine.exporterMasterSecret

            // Add all server messages to outputs
            for (data, msgLevel) in response.messages {
                outputs.insert(.handshakeData(data, level: msgLevel), at: outputs.count - clientHelloOutputs.count)
            }

        case .finished:
            let finishedOutputs = try serverMachine.processClientFinished(content)
            outputs = finishedOutputs

            // Update state
            state.negotiatedALPN = serverMachine.negotiatedALPN
            state.handshakeComplete = true

        default:
            throw TLSError.unexpectedMessage("Unexpected message type \(type) for server")
        }

        return outputs
    }
}

// MARK: - Server State Machine

/// Server-side TLS 1.3 state machine
public final class ServerStateMachine: Sendable {

    private let state = Mutex<ServerState>(ServerState())
    private let configuration: TLSConfiguration

    private struct ServerState: Sendable {
        var handshakeState: ServerHandshakeState = .start
        var context: HandshakeContext = HandshakeContext()
    }

    public init(configuration: TLSConfiguration) {
        self.configuration = configuration
    }

    /// Response from processing ClientHello
    public struct ClientHelloResponse: Sendable {
        public let messages: [(Data, EncryptionLevel)]
    }

    /// Process ClientHello and generate server response
    public func processClientHello(
        _ data: Data,
        transportParameters: Data
    ) throws -> (response: ClientHelloResponse, outputs: [TLSOutput]) {
        return try state.withLock { state in
            // Check if this is ClientHello2 (after HelloRetryRequest)
            let isClientHello2 = state.handshakeState == .sentHelloRetryRequest

            guard state.handshakeState == .start || isClientHello2 else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected ClientHello")
            }

            let clientHello = try ClientHello.decode(from: data)

            // Verify TLS 1.3 support
            guard let supportedVersions = clientHello.supportedVersions,
                  supportedVersions.supportsTLS13 else {
                throw TLSHandshakeError.unsupportedVersion
            }

            // Find common cipher suite
            guard clientHello.cipherSuites.contains(.tls_aes_128_gcm_sha256) else {
                throw TLSHandshakeError.noCipherSuiteMatch
            }
            state.context.cipherSuite = .tls_aes_128_gcm_sha256

            // Get client's key share extension
            guard let clientKeyShare = clientHello.keyShare else {
                throw TLSHandshakeError.noKeyShareMatch
            }

            // Negotiate key exchange group
            let serverSupportedGroups = configuration.supportedGroups
            var selectedGroup: NamedGroup?
            var selectedKeyShareEntry: KeyShareEntry?

            if isClientHello2 {
                // ClientHello2: Must use the group we requested in HRR
                guard let requestedGroup = state.context.helloRetryRequestGroup,
                      let entry = clientKeyShare.keyShare(for: requestedGroup) else {
                    throw TLSHandshakeError.noKeyShareMatch
                }
                selectedGroup = requestedGroup
                selectedKeyShareEntry = entry
            } else {
                // ClientHello1: Find first server-preferred group that client offers
                for group in serverSupportedGroups {
                    if let entry = clientKeyShare.keyShare(for: group) {
                        selectedGroup = group
                        selectedKeyShareEntry = entry
                        break
                    }
                }

                // If no matching key share, try to send HelloRetryRequest
                if selectedGroup == nil {
                    // Check if client supports any of our groups
                    let clientSupportedGroups = clientHello.supportedGroups?.namedGroups ?? []
                    if let commonGroup = serverSupportedGroups.first(where: { clientSupportedGroups.contains($0) }) {
                        return try sendHelloRetryRequest(
                            clientHello: clientHello,
                            clientHelloData: data,
                            requestedGroup: commonGroup,
                            state: &state
                        )
                    }
                    throw TLSHandshakeError.noKeyShareMatch
                }
            }

            guard let selectedGroup = selectedGroup,
                  let peerKeyShareEntry = selectedKeyShareEntry else {
                throw TLSHandshakeError.noKeyShareMatch
            }

            // Extract transport parameters (required for QUIC)
            guard let peerTransportParams = clientHello.quicTransportParameters else {
                throw TLSHandshakeError.missingExtension("quic_transport_parameters")
            }
            state.context.peerTransportParameters = peerTransportParams
            state.context.localTransportParameters = transportParameters

            // Store client values
            state.context.clientRandom = clientHello.random
            state.context.sessionID = clientHello.legacySessionID

            // Update transcript with ClientHello
            let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: data)
            state.context.transcriptHash.update(with: clientHelloMessage)

            // Generate server key pair for selected group
            let serverKeyExchange = try KeyExchange.generate(for: selectedGroup)
            state.context.keyExchange = serverKeyExchange

            // Perform key agreement
            let sharedSecret = try serverKeyExchange.sharedSecret(with: peerKeyShareEntry.keyExchange)
            state.context.sharedSecret = sharedSecret

            // Negotiate ALPN (required for QUIC per RFC 9001)
            guard let clientALPN = clientHello.alpn else {
                throw TLSHandshakeError.noALPNMatch
            }
            if let common = configuration.alpnProtocols.isEmpty ? clientALPN.protocols.first :
                ALPNExtension(protocols: configuration.alpnProtocols).negotiate(with: clientALPN) {
                state.context.negotiatedALPN = common
            } else {
                throw TLSHandshakeError.noALPNMatch
            }

            var messages: [(Data, EncryptionLevel)] = []
            var outputs: [TLSOutput] = []

            // Generate ServerHello
            let serverHello = ServerHello(
                legacySessionIDEcho: clientHello.legacySessionID,
                cipherSuite: .tls_aes_128_gcm_sha256,
                extensions: [
                    .supportedVersionsServer(TLSConstants.version13),
                    .keyShareServer(serverKeyExchange.keyShareEntry())
                ]
            )

            let serverHelloMessage = serverHello.encodeAsHandshake()
            state.context.transcriptHash.update(with: serverHelloMessage)
            messages.append((serverHelloMessage, .initial))

            // Derive handshake secrets
            let transcriptHash = state.context.transcriptHash.currentHash()
            let (clientSecret, serverSecret) = try state.context.keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcriptHash
            )

            state.context.clientHandshakeSecret = clientSecret
            state.context.serverHandshakeSecret = serverSecret

            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .handshake,
                clientSecret: clientSecret,
                serverSecret: serverSecret
            )))

            // Generate EncryptedExtensions
            var eeExtensions: [TLSExtension] = []
            if let alpn = state.context.negotiatedALPN {
                eeExtensions.append(.alpn(ALPNExtension(protocols: [alpn])))
            }
            eeExtensions.append(.quicTransportParameters(transportParameters))

            let encryptedExtensions = EncryptedExtensions(extensions: eeExtensions)
            let eeMessage = encryptedExtensions.encodeAsHandshake()
            state.context.transcriptHash.update(with: eeMessage)
            messages.append((eeMessage, .handshake))

            // Generate Certificate and CertificateVerify if we have certificate material
            if let signingKey = self.configuration.signingKey,
               let certChain = self.configuration.certificateChain,
               !certChain.isEmpty {

                // Generate Certificate message
                let certificate = Certificate(certificates: certChain)
                let certMessage = certificate.encodeAsHandshake()
                state.context.transcriptHash.update(with: certMessage)
                messages.append((certMessage, .handshake))

                // Generate CertificateVerify signature
                // The signature is over the transcript up to (but not including) CertificateVerify
                let transcriptForCV = state.context.transcriptHash.currentHash()
                let signatureContent = CertificateVerify.constructSignatureContent(
                    transcriptHash: transcriptForCV,
                    isServer: true
                )

                let signature = try signingKey.sign(signatureContent)
                let certificateVerify = CertificateVerify(
                    algorithm: signingKey.scheme,
                    signature: signature
                )
                let cvMessage = certificateVerify.encodeAsHandshake()
                state.context.transcriptHash.update(with: cvMessage)
                messages.append((cvMessage, .handshake))
            }

            // Generate server Finished
            let serverFinishedKey = state.context.keySchedule.finishedKey(from: serverSecret)
            let finishedTranscript = state.context.transcriptHash.currentHash()
            let serverVerifyData = state.context.keySchedule.finishedVerifyData(
                forKey: serverFinishedKey,
                transcriptHash: finishedTranscript
            )

            let serverFinished = Finished(verifyData: serverVerifyData)
            let serverFinishedMessage = serverFinished.encodeAsHandshake()
            state.context.transcriptHash.update(with: serverFinishedMessage)
            messages.append((serverFinishedMessage, .handshake))

            // Derive application secrets
            let appTranscriptHash = state.context.transcriptHash.currentHash()
            let (clientAppSecret, serverAppSecret) = try state.context.keySchedule.deriveApplicationSecrets(
                transcriptHash: appTranscriptHash
            )

            state.context.clientApplicationSecret = clientAppSecret
            state.context.serverApplicationSecret = serverAppSecret

            // Derive exporter master secret
            let exporterMasterSecret = try state.context.keySchedule.deriveExporterMasterSecret(
                transcriptHash: appTranscriptHash
            )
            state.context.exporterMasterSecret = exporterMasterSecret

            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .application,
                clientSecret: clientAppSecret,
                serverSecret: serverAppSecret
            )))

            // Transition state
            state.handshakeState = .waitFinished

            return (ClientHelloResponse(messages: messages), outputs)
        }
    }

    /// Send HelloRetryRequest when client's key_share doesn't contain a supported group
    /// RFC 8446 Section 4.1.4
    private func sendHelloRetryRequest(
        clientHello: ClientHello,
        clientHelloData: Data,
        requestedGroup: NamedGroup,
        state: inout ServerState
    ) throws -> (response: ClientHelloResponse, outputs: [TLSOutput]) {
        // Prevent multiple HRRs (RFC 8446: at most one HRR per connection)
        guard !state.context.sentHelloRetryRequest else {
            throw TLSHandshakeError.unexpectedMessage("Multiple HelloRetryRequest not allowed")
        }

        // Mark that we're sending HRR
        state.context.sentHelloRetryRequest = true
        state.context.helloRetryRequestGroup = requestedGroup

        // RFC 8446 Section 4.4.1: Transcript hash special handling for HRR
        // First, compute hash of ClientHello1
        let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: clientHelloData)
        state.context.transcriptHash.update(with: clientHelloMessage)
        let ch1Hash = state.context.transcriptHash.currentHash()

        // Replace transcript with message_hash synthetic message
        // message_hash = Handshake(254) + 00 00 Hash.length + Hash(ClientHello1)
        state.context.transcriptHash = TranscriptHash.fromMessageHash(
            clientHello1Hash: ch1Hash,
            cipherSuite: .tls_aes_128_gcm_sha256
        )

        // Generate HelloRetryRequest
        // HRR is a ServerHello with special random (SHA-256 of "HelloRetryRequest")
        let hrr = ServerHello.helloRetryRequest(
            legacySessionIDEcho: clientHello.legacySessionID,
            cipherSuite: .tls_aes_128_gcm_sha256,
            extensions: [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShare(.helloRetryRequest(KeyShareHelloRetryRequest(selectedGroup: requestedGroup)))
            ]
        )

        let hrrMessage = hrr.encodeAsHandshake()
        state.context.transcriptHash.update(with: hrrMessage)

        // Store cipher suite for later
        state.context.cipherSuite = .tls_aes_128_gcm_sha256

        // Transition state to wait for ClientHello2
        state.handshakeState = .sentHelloRetryRequest

        return (
            ClientHelloResponse(messages: [(hrrMessage, .initial)]),
            []  // No keys available yet, handshake continues after ClientHello2
        )
    }

    /// Process client Finished message
    public func processClientFinished(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitFinished else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client Finished")
            }

            let clientFinished = try Finished.decode(from: data)

            // Verify client Finished
            guard let clientHandshakeSecret = state.context.clientHandshakeSecret else {
                throw TLSHandshakeError.internalError("Missing client handshake secret")
            }

            let clientFinishedKey = state.context.keySchedule.finishedKey(from: clientHandshakeSecret)
            let transcriptHash = state.context.transcriptHash.currentHash()
            let expectedVerifyData = state.context.keySchedule.finishedVerifyData(
                forKey: clientFinishedKey,
                transcriptHash: transcriptHash
            )

            guard clientFinished.verify(expected: expectedVerifyData) else {
                throw TLSHandshakeError.finishedVerificationFailed
            }

            // Update transcript
            let message = HandshakeCodec.encode(type: .finished, content: data)
            state.context.transcriptHash.update(with: message)

            // Transition state
            state.handshakeState = .connected

            return [
                .handshakeComplete(HandshakeCompleteInfo(
                    alpn: state.context.negotiatedALPN,
                    zeroRTTAccepted: false,
                    resumptionTicket: nil
                ))
            ]
        }
    }

    /// Negotiated ALPN protocol
    public var negotiatedALPN: String? {
        state.withLock { $0.context.negotiatedALPN }
    }

    /// Peer transport parameters
    public var peerTransportParameters: Data? {
        state.withLock { $0.context.peerTransportParameters }
    }

    /// Whether handshake is complete
    public var isConnected: Bool {
        state.withLock { $0.handshakeState == .connected }
    }

    /// Exporter master secret (available after handshake completion)
    public var exporterMasterSecret: SymmetricKey? {
        state.withLock { $0.context.exporterMasterSecret }
    }
}
