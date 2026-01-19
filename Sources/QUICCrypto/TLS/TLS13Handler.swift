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

        // Session resumption configuration (set before startHandshake)
        var resumptionTicket: SessionTicketData?
        var attemptEarlyData: Bool = false

        // 0-RTT state tracking
        var is0RTTAttempted: Bool = false
        var is0RTTAccepted: Bool = false
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

                // Pass session ticket and early data flag to ClientStateMachine
                let (clientHello, outputs) = try clientMachine.startHandshake(
                    configuration: configuration,
                    transportParameters: state.localTransportParams ?? Data(),
                    sessionTicket: state.resumptionTicket,
                    attemptEarlyData: state.attemptEarlyData
                )

                // Track if 0-RTT was attempted
                state.is0RTTAttempted = state.attemptEarlyData && state.resumptionTicket != nil

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

            // Get cipher suite from key schedule
            let cipherSuite = state.keySchedule.cipherSuite.toQUICCipherSuite

            return [
                .keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: nextClientSecret,
                    serverSecret: nextServerSecret,
                    cipherSuite: cipherSuite
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
            // Update 0-RTT acceptance status from client state machine
            if state.is0RTTAttempted {
                state.is0RTTAccepted = clientMachine.earlyDataAccepted
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
    private let sessionTicketStore: SessionTicketStore?

    private struct ServerState: Sendable {
        var handshakeState: ServerHandshakeState = .start
        var context: HandshakeContext = HandshakeContext()
    }

    public init(configuration: TLSConfiguration, sessionTicketStore: SessionTicketStore? = nil) {
        self.configuration = configuration
        self.sessionTicketStore = sessionTicketStore
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

            // Try PSK validation if offered
            var pskValidationResult: PSKValidationResult = .noPskOffered
            var selectedPskIndex: UInt16? = nil

            if let offeredPsks = clientHello.preSharedKey,
               let store = self.sessionTicketStore {
                // Compute truncated transcript for binder validation
                // ClientHello without binders section
                let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: data)
                let bindersSize = offeredPsks.bindersSize
                let truncatedLength = clientHelloMessage.count - bindersSize
                let truncatedTranscript = clientHelloMessage.prefix(truncatedLength)

                // Try each offered PSK identity
                for (index, identity) in offeredPsks.identities.enumerated() {
                    guard let session = store.lookupSession(ticketId: identity.identity) else {
                        continue
                    }

                    // Validate ticket age
                    guard session.isValidAge(obfuscatedAge: identity.obfuscatedTicketAge) else {
                        continue
                    }

                    // Get the corresponding binder
                    guard index < offeredPsks.binders.count else {
                        continue
                    }
                    let binder = offeredPsks.binders[index]

                    // Derive PSK from session using the stored ticket nonce
                    let ticketNonce = session.ticketNonce

                    // Initialize key schedule with PSK
                    var pskKeySchedule = TLSKeySchedule(cipherSuite: session.cipherSuite)
                    let psk = session.derivePSK(ticketNonce: ticketNonce, keySchedule: pskKeySchedule)
                    pskKeySchedule.deriveEarlySecret(psk: psk)

                    // Validate binder
                    if let binderKey = try? pskKeySchedule.deriveBinderKey(isResumption: true) {
                        let helper = PSKBinderHelper(cipherSuite: session.cipherSuite)
                        let binderKeyData = binderKey.withUnsafeBytes { Data($0) }
                        // Use cipher suite's hash algorithm (SHA-256 or SHA-384)
                        let transcriptHash = session.cipherSuite.transcriptHash(of: truncatedTranscript)

                        if helper.isValidBinder(forKey: binderKeyData, transcriptHash: transcriptHash, expected: binder) {
                            // PSK validated successfully
                            selectedPskIndex = UInt16(index)
                            state.context.pskUsed = true
                            state.context.selectedPskIdentity = UInt16(index)
                            state.context.cipherSuite = session.cipherSuite
                            pskValidationResult = .valid(index: UInt16(index), session: session, psk: psk)
                            break
                        }
                    }
                }
            }

            // Update transcript with ClientHello (after PSK validation which needs truncated transcript)
            let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: data)
            state.context.transcriptHash.update(with: clientHelloMessage)

            // If PSK was validated, derive early secret in the main key schedule
            if selectedPskIndex != nil,
               case .valid(_, let session, let psk) = pskValidationResult {
                state.context.keySchedule = TLSKeySchedule(cipherSuite: session.cipherSuite)
                state.context.keySchedule.deriveEarlySecret(psk: psk)

                // Check if client offered early_data and session allows it
                if clientHello.earlyData && session.maxEarlyDataSize > 0 {
                    // Accept early data
                    state.context.earlyDataState.attemptingEarlyData = true
                    state.context.earlyDataState.earlyDataAccepted = true
                    state.context.earlyDataState.maxEarlyDataSize = session.maxEarlyDataSize

                    // Derive client early traffic secret (RFC 8446 Section 7.1)
                    let earlyTranscript = state.context.transcriptHash.currentHash()
                    if let earlyTrafficSecret = try? state.context.keySchedule.deriveClientEarlyTrafficSecret(
                        transcriptHash: earlyTranscript
                    ) {
                        state.context.clientEarlyTrafficSecret = earlyTrafficSecret
                        let secretData = earlyTrafficSecret.withUnsafeBytes { Data($0) }
                        state.context.earlyDataState.clientEarlyTrafficSecret = secretData
                    }
                }
            } else {
                // No PSK - derive early secret with nil PSK
                state.context.keySchedule.deriveEarlySecret(psk: nil)
            }

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

            // Build ServerHello extensions
            var serverHelloExtensions: [TLSExtension] = [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShareServer(serverKeyExchange.keyShareEntry())
            ]

            // Add pre_shared_key extension if PSK was accepted
            if let pskIndex = selectedPskIndex {
                serverHelloExtensions.append(.preSharedKeyServer(selectedIdentity: pskIndex))
            }

            // Generate ServerHello
            let serverHello = ServerHello(
                legacySessionIDEcho: clientHello.legacySessionID,
                cipherSuite: state.context.cipherSuite ?? .tls_aes_128_gcm_sha256,
                extensions: serverHelloExtensions
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

            // Get cipher suite for packet protection
            let cipherSuite = (state.context.cipherSuite ?? .tls_aes_128_gcm_sha256).toQUICCipherSuite

            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .handshake,
                clientSecret: clientSecret,
                serverSecret: serverSecret,
                cipherSuite: cipherSuite
            )))

            // Generate EncryptedExtensions
            var eeExtensions: [TLSExtension] = []
            if let alpn = state.context.negotiatedALPN {
                eeExtensions.append(.alpn(ALPNExtension(protocols: [alpn])))
            }
            eeExtensions.append(.quicTransportParameters(transportParameters))

            // Add early_data extension if we accepted it (RFC 8446 Section 4.2.10)
            if state.context.earlyDataState.earlyDataAccepted {
                eeExtensions.append(.earlyData(.encryptedExtensions))

                // Output 0-RTT keys
                if let earlyTrafficSecret = state.context.clientEarlyTrafficSecret {
                    outputs.append(.keysAvailable(KeysAvailableInfo(
                        level: .zeroRTT,
                        clientSecret: earlyTrafficSecret,
                        serverSecret: nil,  // Server doesn't send 0-RTT
                        cipherSuite: cipherSuite
                    )))
                }
            }

            let encryptedExtensions = EncryptedExtensions(extensions: eeExtensions)
            let eeMessage = encryptedExtensions.encodeAsHandshake()
            state.context.transcriptHash.update(with: eeMessage)
            messages.append((eeMessage, .handshake))

            // Generate Certificate and CertificateVerify if we have certificate material
            // Skip for PSK-only handshakes (RFC 8446 Section 2.3)
            if !state.context.pskUsed {
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
                serverSecret: serverAppSecret,
                cipherSuite: cipherSuite
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

            // Derive resumption master secret (RFC 8446 Section 7.1)
            let resumptionTranscript = state.context.transcriptHash.currentHash()
            let resumptionMasterSecret = try state.context.keySchedule.deriveResumptionMasterSecret(
                transcriptHash: resumptionTranscript
            )
            state.context.resumptionMasterSecret = resumptionMasterSecret

            // Transition state
            state.handshakeState = .connected

            return [
                .handshakeComplete(HandshakeCompleteInfo(
                    alpn: state.context.negotiatedALPN,
                    zeroRTTAccepted: state.context.earlyDataState.earlyDataAccepted,
                    resumptionTicket: nil
                ))
            ]
        }
    }

    /// Generate a NewSessionTicket for the client
    /// Call this after handshake completion to enable session resumption
    public func generateNewSessionTicket(
        maxEarlyDataSize: UInt32 = 0,
        lifetime: UInt32 = 86400
    ) throws -> (ticket: NewSessionTicket, data: Data) {
        return try state.withLock { state in
            guard state.handshakeState == .connected else {
                throw TLSHandshakeError.internalError("Cannot generate ticket before handshake completion")
            }

            guard let store = sessionTicketStore else {
                throw TLSHandshakeError.internalError("No session ticket store configured")
            }

            guard let resumptionMasterSecret = state.context.resumptionMasterSecret else {
                throw TLSHandshakeError.internalError("Missing resumption master secret")
            }

            // Generate random ticket_age_add
            var ticketAgeAdd: UInt32 = 0
            withUnsafeMutableBytes(of: &ticketAgeAdd) { ptr in
                _ = SecRandomCopyBytes(kSecRandomDefault, 4, ptr.baseAddress!)
            }

            // Create stored session
            let session = SessionTicketStore.StoredSession(
                resumptionMasterSecret: resumptionMasterSecret,
                cipherSuite: state.context.cipherSuite ?? .tls_aes_128_gcm_sha256,
                lifetime: lifetime,
                ticketAgeAdd: ticketAgeAdd,
                alpn: state.context.negotiatedALPN,
                maxEarlyDataSize: maxEarlyDataSize
            )

            // Generate ticket through store
            let ticket = store.generateTicket(for: session)

            // Encode as handshake message
            let ticketData = ticket.encodeMessage()

            return (ticket, ticketData)
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

    /// Whether PSK was used for authentication
    public var pskUsed: Bool {
        state.withLock { $0.context.pskUsed }
    }

    /// Resumption master secret (available after handshake completion)
    public var resumptionMasterSecret: SymmetricKey? {
        state.withLock { $0.context.resumptionMasterSecret }
    }
}

// MARK: - Cipher Suite Conversion

extension CipherSuite {
    /// Converts TLS CipherSuite to QUICCipherSuite for packet protection
    public var toQUICCipherSuite: QUICCipherSuite {
        switch self {
        case .tls_chacha20_poly1305_sha256:
            return .chacha20Poly1305Sha256
        case .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384:
            // AES-256-GCM uses SHA-384 for TLS key derivation but
            // QUIC packet protection still uses AES-128-GCM key sizes
            // per RFC 9001 (QUIC only supports AES-128-GCM and ChaCha20)
            return .aes128GcmSha256
        }
    }

    /// Computes transcript hash using the appropriate hash algorithm for this cipher suite
    ///
    /// RFC 8446 Section 4.4.1: The Hash function used for transcript hashing
    /// is the one associated with the cipher suite.
    /// - AES-128-GCM-SHA256, ChaCha20-Poly1305-SHA256: SHA-256
    /// - AES-256-GCM-SHA384: SHA-384
    func transcriptHash(of data: Data) -> Data {
        switch self {
        case .tls_aes_256_gcm_sha384:
            return Data(SHA384.hash(data: data))
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            return Data(SHA256.hash(data: data))
        }
    }
}
