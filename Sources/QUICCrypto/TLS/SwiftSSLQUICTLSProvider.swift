/// Adapter from the canonical `swift-tls/QUICTLS` contract to QUIC's
/// transport-facing provider protocol. QUIC owns CRYPTO offsets and reassembly;
/// this adapter accepts exactly one complete handshake message.
import Foundation
import Crypto
import QUICCore
import QUICTLS
import SSLCore
import SSLQUIC
import SSLTLS
import SSLCrypto
import Synchronization

/// Signature algorithm used by a Pure Swift QUIC TLS identity.
public enum SwiftSSLQUICTLSKeyAlgorithm: Sendable, Hashable {
    case p256
    case ed25519
}

/// Application-owned QUIC TLS certificate and signing material.
///
/// The factory copies these bytes once into the owning `swift-ssl` key and
/// certificate-entry types. No byte conversion occurs on the handshake path.
public struct SwiftSSLQUICTLSIdentity: Sendable {
    public let certificateChain: [Data]
    public let privateKey: Data
    public let keyAlgorithm: SwiftSSLQUICTLSKeyAlgorithm

    public init(
        certificateChain: [Data],
        privateKey: Data,
        keyAlgorithm: SwiftSSLQUICTLSKeyAlgorithm
    ) {
        self.certificateChain = certificateChain
        self.privateKey = privateKey
        self.keyAlgorithm = keyAlgorithm
    }
}

/// Configuration used to construct a role-bound Pure Swift QUIC TLS provider.
///
/// Certificate proof is always performed by `swift-ssl`. Optional validators
/// add application policy (for example, libp2p's PeerID extension) and are
/// invoked inside the canonical TLS handshake before completion.
public struct SwiftSSLQUICTLSConfiguration: Sendable {
    public let identity: SwiftSSLQUICTLSIdentity?
    public let alpnProtocols: [String]
    public let requireClientCertificate: Bool
    public let serverCertificateValidator: (any TLS13ServerCertificateValidating)?
    public let clientCertificateValidator: (any TLS13ClientCertificateValidating)?

    public init(
        identity: SwiftSSLQUICTLSIdentity?,
        alpnProtocols: [String] = [],
        requireClientCertificate: Bool = false,
        serverCertificateValidator:
            (any TLS13ServerCertificateValidating)? = nil,
        clientCertificateValidator:
            (any TLS13ClientCertificateValidating)? = nil
    ) {
        self.identity = identity
        self.alpnProtocols = alpnProtocols
        self.requireClientCertificate = requireClientCertificate
        self.serverCertificateValidator = serverCertificateValidator
        self.clientCertificateValidator = clientCertificateValidator
    }
}

/// Role-bound factory for `SwiftSSLQUICTLSProvider`.
///
/// QUIC's historical provider protocol selects the role in `startHandshake`.
/// This factory keeps that compatibility boundary outside the canonical
/// session: each call creates exactly one client or server session, and the
/// noncopyable private key is consumed by that session exactly once.
public final class SwiftSSLQUICTLSProviderFactory: Sendable {
    private let configuration: SwiftSSLQUICTLSConfiguration

    public init(configuration: SwiftSSLQUICTLSConfiguration) {
        self.configuration = configuration
    }

    public func makeClient() throws -> SwiftSSLQUICTLSProvider {
        try SwiftSSLQUICTLSProvider(
            clientSession: Self.makeClientSession(configuration: configuration)
        )
    }

    public func makeServer() throws -> SwiftSSLQUICTLSProvider {
        try SwiftSSLQUICTLSProvider(
            serverSession: Self.makeServerSession(configuration: configuration)
        )
    }

    private static func makeClientSession(
        configuration: SwiftSSLQUICTLSConfiguration
    ) throws -> QUICTLSClientSession {
        let random = try randomBytes(count: 32)
        let ephemeral = try X25519PrivateKey.generate()
        let instant = try SystemWallClock().now()
        let protocols = try applicationProtocols(configuration.alpnProtocols)
        let identity = try clientIdentity(configuration.identity, at: instant)

        let handshake: QUICTLSClientHandshake
        if let validator = configuration.serverCertificateValidator {
            handshake = try QUICTLSClientHandshake.make(
                random: random.span,
                ephemeralKey: consume ephemeral,
                certificateValidator: validator,
                clientIdentity: consume identity,
                applicationProtocols: protocols,
                transportParameters: Data().span,
                verificationInstant: instant
            )
        } else {
            handshake = try QUICTLSClientHandshake.make(
                random: random.span,
                ephemeralKey: consume ephemeral,
                externalServerTrust: TLS13ExternalServerTrust(),
                clientIdentity: consume identity,
                applicationProtocols: protocols,
                transportParameters: Data().span,
                verificationInstant: instant
            )
        }
        return QUICTLSClientSession(handshake: consume handshake)
    }

    private static func makeServerSession(
        configuration: SwiftSSLQUICTLSConfiguration
    ) throws -> QUICTLSServerSession {
        guard let identity = configuration.identity else {
            throw TLSError.internalError("A server QUIC TLS identity is required")
        }
        let random = try randomBytes(count: 32)
        let ephemeral = try X25519PrivateKey.generate()
        let instant = try SystemWallClock().now()
        let entries = try certificateEntries(identity.certificateChain)
        let signingKey = try signingKey(identity)
        let protocols = try applicationProtocols(configuration.alpnProtocols)
        let selector = try ServerPreferredTLS13ApplicationProtocolSelector(
            supportedProtocols: consume protocols
        )

        let clientAuthentication: TLS13ClientAuthenticationConfiguration?
        if configuration.requireClientCertificate {
            if let validator = configuration.clientCertificateValidator {
                clientAuthentication = TLS13ClientAuthenticationConfiguration(
                    requirement: .required,
                    validator: validator
                )
            } else {
                clientAuthentication = TLS13ClientAuthenticationConfiguration(
                    externalTrust: TLS13ExternalClientTrust(requirement: .required)
                )
            }
        } else {
            clientAuthentication = nil
        }

        let handshake = try QUICTLSServerHandshake.make(
            random: random.span,
            ephemeralKey: consume ephemeral,
            certificateEntries: consume entries,
            signingKey: consume signingKey,
            verificationInstant: instant,
            applicationProtocolSelector: selector,
            clientAuthentication: clientAuthentication,
            transportParameters: Data().span
        )
        return QUICTLSServerSession(handshake: consume handshake)
    }

    private static func randomBytes(
        count: Int
    ) throws -> ContiguousArray<UInt8> {
        var bytes = ContiguousArray<UInt8>(repeating: 0, count: count)
        var destination = bytes.mutableSpan
        try SystemEntropySource().fill(&destination)
        return bytes
    }

    private static func applicationProtocols(
        _ values: [String]
    ) throws -> ContiguousArray<TLS13ApplicationProtocol> {
        var result = ContiguousArray<TLS13ApplicationProtocol>()
        result.reserveCapacity(values.count)
        for value in values {
            result.append(try TLS13ApplicationProtocol(identifier: value.utf8.span))
        }
        return result
    }

    private static func certificateEntries(
        _ certificates: [Data]
    ) throws -> ContiguousArray<TLS13CertificateEntry> {
        guard !certificates.isEmpty else {
            throw TLSError.internalError("A QUIC TLS identity needs a certificate chain")
        }
        var result = ContiguousArray<TLS13CertificateEntry>()
        result.reserveCapacity(certificates.count)
        for certificate in certificates {
            result.append(try TLS13CertificateEntry(certificateDER: certificate.span))
        }
        return result
    }

    private static func signingKey(
        _ identity: SwiftSSLQUICTLSIdentity
    ) throws -> TLS13SigningKey {
        switch identity.keyAlgorithm {
        case .p256:
            let key = try P256PrivateKey(bytes: identity.privateKey.span)
            return TLS13SigningKey(p256: consume key)
        case .ed25519:
            let key = try Ed25519PrivateKey(seed: identity.privateKey.span)
            return TLS13SigningKey(ed25519: consume key)
        }
    }

    private static func clientIdentity(
        _ identity: SwiftSSLQUICTLSIdentity?,
        at instant: VerificationInstant
    ) throws -> TLS13ClientIdentity? {
        guard let identity else { return nil }
        let entries = try certificateEntries(identity.certificateChain)
        let key = try signingKey(identity)
        return try TLS13ClientIdentity(
            certificateEntries: consume entries,
            signingKey: consume key,
            verificationInstant: instant
        )
    }
}

/// A QUIC TLS provider backed exclusively by `swift-ssl`.
///
/// Construction is dependency-injected: certificate policy, credentials, and
/// key exchange are created by the application and handed to the canonical
/// session. This adapter does not parse fragmented CRYPTO frames or select a
/// crypto backend.
public final class SwiftSSLQUICTLSProvider: TLS13Provider, Sendable {
    private enum Session: ~Copyable, Sendable {
        case client(QUICTLSClientSession)
        case server(QUICTLSServerSession)
    }

    private struct State: ~Copyable, Sendable {
        var session: Session
        var localTransportParameters: Data
        var peerTransportParameters: Data?
        var handshakeComplete: Bool
        var negotiatedALPN: String?

        init(session: consuming Session) {
            self.session = consume session
            self.localTransportParameters = Data()
            self.peerTransportParameters = nil
            self.handshakeComplete = false
            self.negotiatedALPN = nil
        }
    }

    private let state: Mutex<State>

    public init(clientSession: consuming QUICTLSClientSession) {
        self.state = Mutex(State(session: .client(consume clientSession)))
    }

    public init(serverSession: consuming QUICTLSServerSession) {
        self.state = Mutex(State(session: .server(consume serverSession)))
    }

    public func startHandshake(isClient: Bool) async throws -> [TLSOutput] {
        try state.withLock { state in
            guard isClient == Self.sessionIsClient(state.session) else {
                throw TLSError.internalError("Canonical QUIC TLS role does not match provider role")
            }
            if !isClient {
                // A server waits for the transport-owned CRYPTO reassembler to
                // deliver ClientHello; there is no initial server flight.
                return []
            }
            let output = try Self.start(session: &state.session)
            return try Self.project(output, state: &state)
        }
    }

    public func processHandshakeData(
        _ data: Data,
        at level: EncryptionLevel
    ) async throws -> [TLSOutput] {
        guard level == .initial || level == .handshake else {
            throw TLSError.unexpectedMessage(
                "QUIC TLS handshake bytes must use initial or handshake level"
            )
        }
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else {
            throw TLSError.unexpectedMessage(
                "Canonical QUIC TLS requires one complete handshake message"
            )
        }
        let messageLength =
            (Int(bytes[1]) << 16) | (Int(bytes[2]) << 8) | Int(bytes[3])
        guard messageLength == bytes.count - 4 else {
            throw TLSError.unexpectedMessage(
                "QUIC transport must reassemble one complete TLS message"
            )
        }

        return try state.withLock { state in
            let inputLevel: QUICTLSHandshakeInputLevel =
                level == .initial ? .initial : .handshake
            let output = try Self.receive(
                session: &state.session,
                bytes: bytes,
                level: inputLevel
            )
            return try Self.project(output, state: &state)
        }
    }

    public func getLocalTransportParameters() -> Data {
        state.withLock { $0.localTransportParameters }
    }

    public func setLocalTransportParameters(_ params: Data) throws {
        try state.withLock { state in
            try Self.configureTransportParameters(
                session: &state.session,
                parameters: params.span
            )
            state.localTransportParameters = params
        }
    }

    public func getPeerTransportParameters() -> Data? {
        state.withLock { state in
            if let peer = state.peerTransportParameters { return peer }
            switch state.session {
            case .client(let session):
                return Self.data(session.receivedTransportParameters)
            case .server(let session):
                return Self.data(session.receivedTransportParameters)
            }
        }
    }

    public var isHandshakeComplete: Bool {
        state.withLock { $0.handshakeComplete }
    }

    public var isClient: Bool {
        state.withLock { Self.sessionIsClient($0.session) }
    }

    public var negotiatedALPN: String? {
        state.withLock { state in
            if let negotiated = state.negotiatedALPN { return negotiated }
            switch state.session {
            case .client(let session):
                return Self.alpn(session.negotiatedApplicationProtocol)
            case .server(let session):
                return Self.alpn(session.negotiatedApplicationProtocol)
            }
        }
    }

    public func requestKeyUpdate() async throws -> [TLSOutput] {
        throw TLSError.internalError(
            "QUIC key updates are owned by the packet protection layer"
        )
    }

    public func exportKeyingMaterial(
        label: String,
        context: Data?,
        length: Int
    ) throws -> Data {
        throw TLSError.internalError(
            "Canonical QUIC TLS exporter is not exposed by the session contract"
        )
    }

    public func configureResumption(
        ticket: SessionTicketData,
        attemptEarlyData: Bool
    ) throws {
        throw TLSError.internalError(
            "Resumption must be supplied when constructing the canonical session"
        )
    }

    public var is0RTTAccepted: Bool { false }
    public var is0RTTAttempted: Bool { false }

    private static func sessionIsClient(_ session: borrowing Session) -> Bool {
        switch session {
        case .client: return true
        case .server: return false
        }
    }

    private static func start(
        session: inout Session
    ) throws -> QUICTLSStepOutput {
        switch consume session {
        case .client(var client):
            do {
                let output = try client.start()
                session = .client(consume client)
                return output
            } catch {
                session = .client(consume client)
                throw error
            }
        case .server(let server):
            session = .server(consume server)
            throw TLSError.internalError("A server session has no client start transition")
        }
    }

    private static func receive(
        session: inout Session,
        bytes: [UInt8],
        level: QUICTLSHandshakeInputLevel
    ) throws -> QUICTLSStepOutput {
        switch consume session {
        case .client(var client):
            do {
                let output = try client.receive(bytes.span, at: level)
                session = .client(consume client)
                return output
            } catch {
                session = .client(consume client)
                throw error
            }
        case .server(var server):
            do {
                let output = try server.receive(bytes.span, at: level)
                session = .server(consume server)
                return output
            } catch {
                session = .server(consume server)
                throw error
            }
        }
    }

    private static func configureTransportParameters(
        session: inout Session,
        parameters: Span<UInt8>
    ) throws {
        switch consume session {
        case .client(var client):
            do {
                try client.configureTransportParameters(parameters)
                session = .client(consume client)
            } catch {
                session = .client(consume client)
                throw error
            }
        case .server(var server):
            do {
                try server.configureTransportParameters(parameters)
                session = .server(consume server)
            } catch {
                session = .server(consume server)
                throw error
            }
        }
    }

    private static func project(
        _ output: consuming QUICTLSStepOutput,
        state: inout State
    ) throws -> [TLSOutput] {
        var output = consume output
        var projected: [TLSOutput] = []
        while let effect = try output.nextEffect() {
            switch effect {
            case .action(let action):
                switch action {
                case .emitHandshakeBytes(let level, let range):
                    let data = output.withBorrowedBytes { bytes in
                        Self.data(bytes.extracting(range.offset..<range.endOffset))
                    }
                    projected.append(
                        .handshakeData(data, level: Self.encryptionLevel(level))
                    )
                case .handshakeComplete:
                    state.handshakeComplete = true
                    state.peerTransportParameters = Self.peerTransportParameters(
                        state.session
                    )
                    state.negotiatedALPN = Self.alpn(
                        Self.applicationProtocol(state.session)
                    )
                    projected.append(
                        .handshakeComplete(
                            HandshakeCompleteInfo(alpn: state.negotiatedALPN)
                        )
                    )
                case .handshakeConfirmed, .earlyDataAccepted, .earlyDataRejected:
                    break
                case .sendAlert(_, let alert):
                    projected.append(
                        .error(
                            .handshakeFailed(
                                alert: alert.rawValue,
                                description: "swift-ssl QUIC TLS alert"
                            )
                        )
                    )
                }
            case .trafficSecret(let event):
                let secret = event.withBorrowedSecret { bytes in
                    SymmetricKey(data: Self.data(bytes))
                }
                let clientSecret: SymmetricKey?
                let serverSecret: SymmetricKey?
                if (Self.sessionIsClient(state.session) && event.direction == .write)
                    || (!Self.sessionIsClient(state.session) && event.direction == .read)
                {
                    clientSecret = secret
                    serverSecret = nil
                } else {
                    clientSecret = nil
                    serverSecret = secret
                }
                projected.append(
                    .keysAvailable(
                        KeysAvailableInfo(
                            level: Self.encryptionLevel(event.level),
                            clientSecret: clientSecret,
                            serverSecret: serverSecret,
                            cipherSuite: try Self.cipherSuite(event.cipherSuite)
                        )
                    )
                )
            }
        }
        return projected
    }

    private static func encryptionLevel(
        _ level: QUICHandshakeEncryptionLevel
    ) -> EncryptionLevel {
        switch level {
        case .initial: return .initial
        case .handshake: return .handshake
        case .oneRTT: return .application
        }
    }

    private static func encryptionLevel(
        _ level: QUICTrafficSecretLevel
    ) -> EncryptionLevel {
        switch level {
        case .zeroRTT: return .zeroRTT
        case .handshake: return .handshake
        case .oneRTT: return .application
        }
    }

    private static func cipherSuite(
        _ suite: TLSCipherSuite
    ) throws -> QUICCipherSuite {
        switch suite {
        case .aes128GCM_SHA256: return .aes128GcmSha256
        case .aes256GCM_SHA384:
            throw TLSError.internalError(
                "The QUIC packet adapter does not support AES-256-GCM"
            )
        case .chacha20Poly1305_SHA256: return .chacha20Poly1305Sha256
        }
    }

    private static func alpn(
        _ protocolValue: TLS13ApplicationProtocol?
    ) -> String? {
        protocolValue?.withIdentifierBytes { bytes in
            String(decoding: Self.data(bytes), as: UTF8.self)
        }
    }

    private static func applicationProtocol(
        _ session: borrowing Session
    ) -> TLS13ApplicationProtocol? {
        switch session {
        case .client(let session): return session.negotiatedApplicationProtocol
        case .server(let session): return session.negotiatedApplicationProtocol
        }
    }

    private static func peerTransportParameters(
        _ session: borrowing Session
    ) -> Data? {
        switch session {
        case .client(let session): return data(session.receivedTransportParameters)
        case .server(let session): return data(session.receivedTransportParameters)
        }
    }

    private static func data(_ bytes: OwnedBytes?) -> Data? {
        bytes?.withBorrowedBytes { data($0) }
    }

    private static func data(_ bytes: Span<UInt8>) -> Data {
        var result = Data()
        result.reserveCapacity(bytes.count)
        for index in 0..<bytes.count { result.append(bytes[index]) }
        return result
    }
}
