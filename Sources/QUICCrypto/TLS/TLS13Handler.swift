/// TLS 1.3 Handler - Main Implementation of TLS13Provider
///
/// Implements the TLS13Provider protocol using pure Swift and swift-crypto.
/// Designed specifically for QUIC (no TLS record layer).

import Foundation
import QUICTLSCore
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

    /// Peer certificates (raw DER data, leaf certificate first)
    /// Available after receiving peer's Certificate message.
    /// For client mode: returns server's certificates
    /// For server mode (mTLS): returns client's certificates
    public var peerCertificates: [Data]? {
        state.withLock { state -> [Data]? in
            if state.isClientMode {
                return state.clientStateMachine?.peerCertificates
            } else {
                // For server in mTLS, the peer is the client
                // Client certificates are stored in clientCertificates, not peerCertificates
                return state.serverStateMachine?.clientCertificates
            }
        }
    }

    /// Parsed peer leaf certificate
    /// Available after receiving peer's Certificate message.
    /// For client mode: returns server's certificate
    /// For server mode (mTLS): returns client's certificate
    public var peerCertificate: X509Certificate? {
        state.withLock { state -> X509Certificate? in
            if state.isClientMode {
                return state.clientStateMachine?.peerCertificate
            } else {
                // For server in mTLS, the peer is the client
                return state.serverStateMachine?.clientCertificate
            }
        }
    }

    /// Validated peer info from certificate validator callback.
    ///
    /// This contains the value returned by `TLSConfiguration.certificateValidator`
    /// after successful certificate validation (e.g., PeerID for libp2p).
    public var validatedPeerInfo: (any Sendable)? {
        state.withLock { state in
            if state.isClientMode {
                return state.clientStateMachine?.validatedPeerInfo
            } else {
                return state.serverStateMachine?.validatedPeerInfo
            }
        }
    }

    /// Requests a QUIC 1-RTT key update (RFC 9001 §6.1).
    ///
    /// The next application traffic secrets are derived with the QUIC "quic ku"
    /// label via ``KeySchedule/nextApplicationTrafficSecret(from:)`` — the single
    /// source of truth shared with the live key-phase rotation
    /// (`KeySchedule.updateKeys()`). This deliberately does NOT use the
    /// TLS-over-TCP "traffic upd" label of RFC 8446 §7.2, which would be wrong for
    /// QUIC and would diverge from the live rotation path.
    public func requestKeyUpdate() async throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeComplete else {
                throw TLSError.unexpectedMessage("Cannot request key update before handshake complete")
            }

            guard let currentClientSecret = state.clientApplicationSecret,
                  let currentServerSecret = state.serverApplicationSecret else {
                throw TLSError.internalError("Application secrets not available for key update")
            }

            // Derive next application traffic secrets (RFC 9001 §6.1, "quic ku").
            let nextClientSecret = try KeySchedule.nextApplicationTrafficSecret(
                from: currentClientSecret
            )
            let nextServerSecret = try KeySchedule.nextApplicationTrafficSecret(
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
        case .encryptedExtensions, .certificateRequest, .certificate, .certificateVerify, .finished:
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

        case .certificateRequest:
            // Server requesting client certificate (mutual TLS)
            outputs = try clientMachine.processCertificateRequest(content)

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

        case .certificate:
            // Client's certificate (for mutual TLS)
            outputs = try serverMachine.processClientCertificate(content)

        case .certificateVerify:
            // Client's CertificateVerify (for mutual TLS)
            outputs = try serverMachine.processClientCertificateVerify(content)

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

        /// The Embedded-clean server handshake FSM. It owns the running transcript +
        /// key schedule by value and performs the ServerHello…Finished flight
        /// mechanics (transcript folding, handshake/application/exporter/resumption
        /// derivations, the HRR `message_hash` transform, the client
        /// CertificateVerify proof-of-possession check, and the client Finished MAC).
        /// The adapter keeps the Mutex, the TLSConfiguration-dependent negotiation +
        /// wire-message assembly, the swift-crypto (EC)DHE + signing, X.509, and the
        /// PSK-binder validation; it specialises the core at
        /// `C = QUICFoundationProvider` and drives it under its lock so transcripts /
        /// secrets and behaviour stay byte-identical.
        var serverHandshake: QUICServerHandshake<QUICFoundationProvider> = .init()
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
            state.context.peerTransportParameters = Data(peerTransportParams)
            state.context.localTransportParameters = transportParameters

            // Store client values
            state.context.clientRandom = Data(clientHello.random)
            state.context.sessionID = Data(clientHello.legacySessionID)

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
                    guard let session = store.lookupSession(ticketId: identity.identityData) else {
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
                    do {
                        let binderKey = try pskKeySchedule.deriveBinderKey(isResumption: true)
                        let helper = PSKBinderHelper(cipherSuite: session.cipherSuite)
                        let binderKeyData = binderKey.withUnsafeBytes { Data($0) }
                        // Use cipher suite's hash algorithm (SHA-256 or SHA-384)
                        let transcriptHash = session.cipherSuite.transcriptHash(of: truncatedTranscript)

                        if helper.isValidBinder(forKey: binderKeyData, transcriptHash: transcriptHash, expected: Data(binder)) {
                            // PSK validated successfully
                            selectedPskIndex = UInt16(index)
                            state.context.pskUsed = true
                            state.context.selectedPskIdentity = UInt16(index)
                            state.context.cipherSuite = session.cipherSuite
                            pskValidationResult = .valid(index: UInt16(index), session: session, psk: psk)
                            break
                        }
                    } catch {
                        continue
                    }
                }
            }

            // Resolve PSK / early-data acceptance (adapter-side negotiation). The
            // accepted PSK material is passed to the core, which installs the early
            // secret and derives the 0-RTT secret.
            let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: data)
            var acceptedPSK: QUICServerHandshake<QUICFoundationProvider>.AcceptedPSK?
            var earlyDataAccepted = false

            if selectedPskIndex != nil,
               case .valid(_, let session, let psk) = pskValidationResult {
                acceptedPSK = .init(
                    psk: psk.withUnsafeBytes { [UInt8]($0) },
                    cipherSuite: session.cipherSuite.coreCipherSuite
                )

                // Check if client offered early_data and session allows it.
                if clientHello.earlyData && session.maxEarlyDataSize > 0 {
                    // Check replay protection if configured (RFC 8446 Section 8). 0-RTT
                    // data can be replayed, so servers should track ticket usage.
                    var acceptEarlyData = true
                    if let replayProtection = configuration.replayProtection {
                        let ticketIdentifier = ReplayProtection.createIdentifier(from: session.ticketNonce)
                        acceptEarlyData = replayProtection.shouldAcceptEarlyData(ticketIdentifier: ticketIdentifier)
                    }
                    if acceptEarlyData {
                        state.context.earlyDataState.attemptingEarlyData = true
                        state.context.earlyDataState.maxEarlyDataSize = session.maxEarlyDataSize
                        earlyDataAccepted = true
                    }
                    // If replay detected, early data is rejected but handshake continues with 1-RTT.
                }
            }

            // Generate server key pair for selected group + perform key agreement
            // (adapter-side, swift-crypto ephemeral key).
            let serverKeyExchange = try KeyExchange.generate(for: selectedGroup)
            state.context.keyExchange = serverKeyExchange
            let sharedSecret = try serverKeyExchange.sharedSecret(with: peerKeyShareEntry.keyExchangeData)
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

            let negotiatedCipherSuite = state.context.cipherSuite ?? .tls_aes_128_gcm_sha256
            let pskAccepted = acceptedPSK != nil

            // Assemble the server flight messages (adapter-side wire assembly).
            var serverHelloExtensions: [TLSExtension] = [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShareServer(serverKeyExchange.keyShareEntry())
            ]
            if let pskIndex = selectedPskIndex {
                serverHelloExtensions.append(.preSharedKeyServer(selectedIdentity: pskIndex))
            }
            let serverHello = ServerHello(
                legacySessionIDEcho: Data(clientHello.legacySessionID),
                cipherSuite: negotiatedCipherSuite,
                extensions: serverHelloExtensions
            )
            let serverHelloMessage = serverHello.encodeAsHandshake()

            var eeExtensions: [TLSExtension] = []
            if let alpn = state.context.negotiatedALPN {
                eeExtensions.append(.alpn(ALPNExtension(protocols: [alpn])))
            }
            eeExtensions.append(.quicTransportParameters(transportParameters))
            if earlyDataAccepted {
                eeExtensions.append(.earlyData(.encryptedExtensions))
            }
            let eeMessage = EncryptedExtensions(extensions: eeExtensions).encodeAsHandshake()

            // CertificateRequest (mTLS), only for non-PSK handshakes.
            var certRequestMessage: Data?
            var certRequestSignatureAlgorithms: [SignatureScheme]?
            if !pskAccepted && self.configuration.requireClientCertificate {
                let certRequest = CertificateRequest.withDefaultSignatureAlgorithms()
                certRequestMessage = certRequest.encodeAsHandshake()
                certRequestSignatureAlgorithms = certRequest.signatureAlgorithms
                state.context.expectingClientCertificate = true
            }

            // Server Certificate (non-PSK).
            var serverCertificateMessage: Data?
            var signingKeyForCV: SigningKey?
            if !pskAccepted {
                guard let signingKey = self.configuration.signingKey,
                      let certChain = self.configuration.certificateChain,
                      !certChain.isEmpty else {
                    throw TLSHandshakeError.certificateRequired
                }
                serverCertificateMessage = Certificate(certificates: certChain).encodeAsHandshake()
                signingKeyForCV = signingKey
            }

            // Drive the server FSM: fold CH → install early secret → derive 0-RTT →
            // fold SH → derive handshake secrets → fold EE/CR/Cert → (non-PSK) request
            // a CertificateVerify signature.
            let flightParameters = QUICServerHandshake<QUICFoundationProvider>.FlightParameters(
                cipherSuite: negotiatedCipherSuite.coreCipherSuite,
                acceptedPSK: acceptedPSK,
                sharedSecret: sharedSecret.withUnsafeBytes { [UInt8]($0) },
                earlyDataAccepted: earlyDataAccepted,
                requestClientCertificate: state.context.expectingClientCertificate,
                certificateRequestSignatureAlgorithms: certRequestSignatureAlgorithms
            )
            let flight = try Self.beginServerFlight(
                &state.serverHandshake,
                clientHelloBytes: [UInt8](clientHelloMessage),
                parameters: flightParameters,
                serverHelloBytes: [UInt8](serverHelloMessage),
                encryptedExtensionsBytes: [UInt8](eeMessage),
                certificateRequestBytes: certRequestMessage.map { [UInt8]($0) },
                serverCertificateBytes: serverCertificateMessage.map { [UInt8]($0) }
            )

            let clientSecret = SymmetricKey(data: flight.handshakeSecrets.client)
            let serverSecret = SymmetricKey(data: flight.handshakeSecrets.server)
            state.context.clientHandshakeSecret = clientSecret
            state.context.serverHandshakeSecret = serverSecret

            var messages: [(Data, EncryptionLevel)] = []
            var outputs: [TLSOutput] = []
            let cipherSuite = negotiatedCipherSuite.toQUICCipherSuite

            messages.append((serverHelloMessage, .initial))
            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .handshake,
                clientSecret: clientSecret,
                serverSecret: serverSecret,
                cipherSuite: cipherSuite
            )))

            // 0-RTT keys (after ServerHello / handshake keys, matching the legacy order).
            if earlyDataAccepted, let earlySecretBytes = flight.clientEarlyTrafficSecret {
                let earlyTrafficSecret = SymmetricKey(data: earlySecretBytes)
                state.context.clientEarlyTrafficSecret = earlyTrafficSecret
                state.context.earlyDataState.earlyDataAccepted = true
                state.context.earlyDataState.clientEarlyTrafficSecret = Data(earlySecretBytes)
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .zeroRTT,
                    clientSecret: earlyTrafficSecret,
                    serverSecret: nil,  // Server doesn't send 0-RTT
                    cipherSuite: cipherSuite
                )))
            }

            messages.append((eeMessage, .handshake))
            if let certRequestMessage {
                messages.append((certRequestMessage, .handshake))
            }
            if let serverCertificateMessage {
                messages.append((serverCertificateMessage, .handshake))
            }

            // Non-PSK: sign the CertificateVerify over the requested transcript hash
            // (adapter-side signing-key path) and fold it back through the core.
            if let cvRequest = flight.certificateVerifyRequest, let signingKey = signingKeyForCV {
                let signatureContent = CertificateVerify.constructSignatureContent(
                    transcriptHash: Data(cvRequest.transcriptHash),
                    isServer: true
                )
                let signature = try signingKey.sign(signatureContent)
                let certificateVerify = CertificateVerify(
                    algorithm: signingKey.scheme,
                    signature: signature
                )
                let cvMessage = certificateVerify.encodeAsHandshake()
                try Self.foldServerCertificateVerify(&state.serverHandshake, messageBytes: [UInt8](cvMessage))
                messages.append((cvMessage, .handshake))
            }

            // Build the server Finished + derive application/exporter secrets.
            let finished = try Self.finishServerFlight(&state.serverHandshake)
            messages.append((Data(finished.serverFinished), .handshake))

            let clientAppSecret = SymmetricKey(data: finished.applicationSecrets.client)
            let serverAppSecret = SymmetricKey(data: finished.applicationSecrets.server)
            state.context.clientApplicationSecret = clientAppSecret
            state.context.serverApplicationSecret = serverAppSecret
            state.context.exporterMasterSecret = SymmetricKey(data: finished.exporterMasterSecret)

            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .application,
                clientSecret: clientAppSecret,
                serverSecret: serverAppSecret,
                cipherSuite: cipherSuite
            )))

            // Mirror the FSM's transition onto the adapter's observable state.
            if state.context.expectingClientCertificate {
                state.handshakeState = .waitClientCertificate
            } else {
                state.handshakeState = .waitFinished
            }

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

        // Generate HelloRetryRequest. HRR is a ServerHello with special random
        // (SHA-256 of "HelloRetryRequest").
        let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: clientHelloData)
        let hrr = ServerHello.helloRetryRequest(
            legacySessionIDEcho: Data(clientHello.legacySessionID),
            cipherSuite: .tls_aes_128_gcm_sha256,
            extensions: [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShare(.helloRetryRequest(KeyShareHelloRetryRequest(selectedGroup: requestedGroup)))
            ]
        )
        let hrrMessage = hrr.encodeAsHandshake()

        // RFC 8446 Section 4.4.1: the server FSM applies the special `message_hash`
        // transcript transform (fold CH1 → message_hash(CH1) → fold HRR). The core
        // owns the transcript, so the synthetic-message bytes stay byte-identical.
        try Self.applyHelloRetryRequest(
            &state.serverHandshake,
            cipherSuite: CipherSuite.tls_aes_128_gcm_sha256.coreCipherSuite,
            clientHello1Bytes: [UInt8](clientHelloMessage),
            helloRetryRequestBytes: [UInt8](hrrMessage)
        )

        // Store cipher suite for later
        state.context.cipherSuite = .tls_aes_128_gcm_sha256

        // Transition state to wait for ClientHello2
        state.handshakeState = .sentHelloRetryRequest

        return (
            ClientHelloResponse(messages: [(hrrMessage, .initial)]),
            []  // No keys available yet, handshake continues after ClientHello2
        )
    }

    /// Process client Certificate message (for mutual TLS)
    ///
    /// RFC 8446 Section 4.4.2: Client sends Certificate in response to CertificateRequest.
    /// The certificate_request_context MUST match what was sent in CertificateRequest.
    public func processClientCertificate(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitClientCertificate else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client Certificate")
            }

            let certificate = try Certificate.decode(from: data)
            let message = HandshakeCodec.encode(type: .certificate, content: data)

            // Check if client sent any certificates
            if certificate.certificates.isEmpty {
                // Client sent empty certificate - fail if we require client auth
                if configuration.requireClientCertificate {
                    throw TLSHandshakeError.certificateRequired
                }
                // No client cert: the FSM folds it and transitions to waitFinished.
                _ = try Self.ingestClientCertificate(
                    &state.serverHandshake,
                    certificatePresented: false,
                    rawMessageBytes: [UInt8](message)
                )
                state.handshakeState = .waitFinished
                return []
            }

            // Store client certificates
            state.context.clientCertificates = certificate.certificatesData

            // Parse leaf certificate for verification (X.509 stays adapter-side).
            guard let leafCertData = certificate.certificatesData.first else {
                throw TLSHandshakeError.certificateVerificationFailed("No leaf certificate")
            }
            let leafCert = try X509Certificate.parse(from: leafCertData)
            state.context.clientCertificate = leafCert
            state.context.clientVerificationKey = try leafCert.extractPublicKey()

            // The FSM folds the Certificate and transitions to waitClientCertificateVerify.
            _ = try Self.ingestClientCertificate(
                &state.serverHandshake,
                certificatePresented: true,
                rawMessageBytes: [UInt8](message)
            )
            state.handshakeState = .waitClientCertificateVerify

            return []
        }
    }

    /// Process client CertificateVerify message (for mutual TLS)
    ///
    /// RFC 8446 Section 4.4.3: Verifies client's signature over the transcript.
    /// The signature context is "TLS 1.3, client CertificateVerify".
    public func processClientCertificateVerify(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitClientCertificateVerify else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client CertificateVerify")
            }

            let certificateVerify = try CertificateVerify.decode(from: data)

            // Get verification key from client's certificate (X.509 stays adapter-side).
            guard let verificationKey = state.context.clientVerificationKey else {
                throw TLSHandshakeError.internalError("Missing client verification key")
            }

            // Verify (fail-closed) + fold via the FSM. The FSM holds the live
            // transcript, so the signed content is byte-identical; the
            // proof-of-possession check runs through the seam verifier.
            let message = HandshakeCodec.encode(type: .certificateVerify, content: data)
            try Self.ingestClientCertificateVerify(
                &state.serverHandshake,
                algorithm: certificateVerify.algorithm,
                signature: certificateVerify.signature,
                clientPublicKey: .init(
                    bytes: [UInt8](verificationKey.publicKeyBytes),
                    scheme: verificationKey.scheme
                ),
                rawMessageBytes: [UInt8](message)
            )

            // Call custom certificate validator if configured
            if let validator = configuration.certificateValidator,
               let clientCerts = state.context.clientCertificates {
                let peerInfo = try validator(clientCerts)
                state.context.validatedPeerInfo = peerInfo
            }

            // Transition to wait for Finished
            state.handshakeState = .waitFinished

            return []
        }
    }

    /// Process client Finished message
    public func processClientFinished(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitFinished else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client Finished")
            }

            let clientFinished = try Finished.decode(from: data)

            // Verify the client Finished MAC (constant-time), fold it, and derive the
            // resumption master secret — all inside the FSM, fail-closed.
            try Self.ingestClientFinished(
                &state.serverHandshake,
                verifyData: [UInt8](clientFinished.verifyData)
            )
            if let resumption = state.serverHandshake.resumptionMasterSecret {
                state.context.resumptionMasterSecret = SymmetricKey(data: resumption)
            }

            // Keep the adapter's key-schedule bridge in sync so post-handshake paths
            // (NewSessionTicket) observe the completed state.
            state.context.keySchedule.coreValue = state.serverHandshake.currentKeySchedule

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
            let ticketAgeAdd = SecureRandom.uint32()

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

    /// Peer certificates (raw DER data, leaf certificate first)
    public var peerCertificates: [Data]? {
        state.withLock { $0.context.peerCertificates }
    }

    /// Validated peer info from certificate validator callback.
    ///
    /// This contains the value returned by `TLSConfiguration.certificateValidator`
    /// after successful certificate validation (e.g., PeerID for libp2p).
    public var validatedPeerInfo: (any Sendable)? {
        state.withLock { $0.context.validatedPeerInfo }
    }

    /// Client certificates received from peer (server-side, for mTLS).
    public var clientCertificates: [Data]? {
        state.withLock { $0.context.clientCertificates }
    }

    /// Parsed client leaf certificate (server-side, for mTLS).
    public var clientCertificate: X509Certificate? {
        state.withLock { $0.context.clientCertificate }
    }

    /// Parsed peer leaf certificate
    public var peerCertificate: X509Certificate? {
        state.withLock { $0.context.peerCertificate }
    }

    // MARK: - Server FSM bridges
    //
    // The mutating core calls live in dedicated `inout`-FSM helpers (not driven via
    // the `inout ServerState`/`withLock` closures) so the typed error mapping is
    // isolated and the FSM ownership transfer stays simple for the compiler. Each
    // helper uses a bare `catch` (no `as`) because the wrapped call uses typed
    // throws, so `error` is statically a `QUICServerHandshakeError`.

    /// Applies the HelloRetryRequest `message_hash` transform on the FSM.
    private static func applyHelloRetryRequest(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>,
        cipherSuite: TLSCipherSuiteCore,
        clientHello1Bytes: [UInt8],
        helloRetryRequestBytes: [UInt8]
    ) throws {
        do {
            try handshake.applyHelloRetryRequest(
                cipherSuite: cipherSuite,
                clientHello1Bytes: clientHello1Bytes,
                helloRetryRequestBytes: helloRetryRequestBytes
            )
        } catch {
            throw TLSHandshakeError.from(error)
        }
    }

    /// Begins the server flight through the FSM.
    private static func beginServerFlight(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>,
        clientHelloBytes: [UInt8],
        parameters: QUICServerHandshake<QUICFoundationProvider>.FlightParameters,
        serverHelloBytes: [UInt8],
        encryptedExtensionsBytes: [UInt8],
        certificateRequestBytes: [UInt8]?,
        serverCertificateBytes: [UInt8]?
    ) throws -> (
        handshakeSecrets: (client: [UInt8], server: [UInt8]),
        clientEarlyTrafficSecret: [UInt8]?,
        certificateVerifyRequest: QUICServerHandshake<QUICFoundationProvider>.ServerCertificateVerifyRequest?
    ) {
        do {
            return try handshake.beginServerFlight(
                clientHelloBytes: clientHelloBytes,
                parameters: parameters,
                serverHelloBytes: serverHelloBytes,
                encryptedExtensionsBytes: encryptedExtensionsBytes,
                certificateRequestBytes: certificateRequestBytes,
                serverCertificateBytes: serverCertificateBytes
            )
        } catch {
            throw TLSHandshakeError.from(error)
        }
    }

    /// Folds the adapter-signed server CertificateVerify through the FSM.
    private static func foldServerCertificateVerify(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>,
        messageBytes: [UInt8]
    ) throws {
        do {
            try handshake.foldServerCertificateVerify(messageBytes: messageBytes)
        } catch {
            throw TLSHandshakeError.from(error)
        }
    }

    /// Finishes the server flight (Finished + application/exporter secrets).
    private static func finishServerFlight(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>
    ) throws -> (
        serverFinished: [UInt8],
        applicationSecrets: (client: [UInt8], server: [UInt8]),
        exporterMasterSecret: [UInt8]
    ) {
        do {
            return try handshake.finishServerFlight()
        } catch {
            throw TLSHandshakeError.from(error)
        }
    }

    /// Ingests the client Certificate through the FSM.
    private static func ingestClientCertificate(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>,
        certificatePresented: Bool,
        rawMessageBytes: [UInt8]
    ) throws -> Bool {
        do {
            return try handshake.ingestClientCertificate(
                certificatePresented: certificatePresented,
                rawMessageBytes: rawMessageBytes
            )
        } catch {
            throw TLSHandshakeError.from(error)
        }
    }

    /// Ingests + verifies the client CertificateVerify through the FSM.
    private static func ingestClientCertificateVerify(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>,
        algorithm: SignatureScheme,
        signature: [UInt8],
        clientPublicKey: QUICServerHandshake<QUICFoundationProvider>.ClientPublicKey,
        rawMessageBytes: [UInt8]
    ) throws {
        do {
            try handshake.ingestClientCertificateVerify(
                algorithm: algorithm,
                signature: signature,
                clientPublicKey: clientPublicKey,
                rawMessageBytes: rawMessageBytes
            )
        } catch {
            throw TLSHandshakeError.from(error)
        }
    }

    /// Ingests + verifies the client Finished through the FSM.
    private static func ingestClientFinished(
        _ handshake: inout QUICServerHandshake<QUICFoundationProvider>,
        verifyData: [UInt8]
    ) throws {
        do {
            try handshake.ingestClientFinished(verifyData: verifyData)
        } catch {
            throw TLSHandshakeError.from(error)
        }
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
