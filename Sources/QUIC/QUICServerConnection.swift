import Synchronization
import NetworkingCore
import NetworkingDatagram
import NetworkingTime
import QUICTLS
import QUICConnectionCore
import QUICConnectionEngineCore
import QUICWire

/// One accepted server-side QUIC session. Listener routing and connection-ID
/// demultiplexing remain separate transport responsibilities.
public final class QUICServerConnection<
    Environment: QUICServerRuntimeEnvironment
>: Sendable {
    private let connection: QUICEngineConnection<Environment>
    private let tls: Mutex<QUICTLSServerSession>
    private let capabilities: Environment.Capabilities
    private let lifecycle = Mutex(Lifecycle())

    private struct Lifecycle: Sendable {
        var runStarted = false
        var peerTransportParametersApplied = false
        var handshakeOutputFlushed = false
    }

    public init(
        configuration suppliedConfiguration: QUICConnectionEngineConfiguration,
        tlsSession suppliedTLSSession: consuming QUICTLSServerSession,
        capabilityProvider: Environment.Capabilities,
        transport: Environment.Transport,
        timer: Environment.Timer,
        peer: IPSocketEndpoint
    ) throws(QUICConnectionDriverError) {
        guard suppliedConfiguration.role == .server else {
            throw .engine(
                .invalidState("QUICServerConnection requires a server engine configuration")
            )
        }

        var configuration = suppliedConfiguration
        configuration.localTransportParameters.initialSourceConnectionID =
            configuration.localConnectionID
        configuration.localTransportParameters.originalDestinationConnectionID =
            configuration.originalDestinationConnectionID
        configuration.localTransportParameters.retrySourceConnectionID = nil

        var tlsSession = consume suppliedTLSSession
        let localParameters: [UInt8]
        do throws(TransportParameterCodecError) {
            localParameters = try TransportParameterCodecCore.encode(
                configuration.localTransportParameters
            )
        } catch let error {
            throw .transportParameters(error)
        }
        do throws(QUICTLSHandshakeError) {
            try tlsSession.configureTransportParameters(localParameters.span)
        } catch let error {
            throw .tls(error)
        }

        let now: MonotonicInstant
        do throws(TimeError) {
            now = try timer.now()
        } catch let error {
            throw .time(error)
        }

        let engine: QUICConnectionEngine
        do throws(QUICEngineError) {
            engine = try QUICConnectionEngine(
                configuration: configuration,
                nowNanos: now.nanoseconds
            )
        } catch let error {
            throw .engine(error)
        }

        connection = QUICEngineConnection<Environment>(
            engine: engine,
            transport: transport,
            timer: timer,
            peer: peer
        )
        tls = Mutex(consume tlsSession)
        capabilities = capabilityProvider
    }

    public func run() async throws(QUICConnectionDriverError) {
        let canStart = lifecycle.withLock { state -> Bool in
            guard !state.runStarted else { return false }
            state.runStarted = true
            return true
        }
        guard canStart else {
            throw .engine(.invalidState("QUICServerConnection.run() may be called only once"))
        }

        let handler: QUICHandshakeHandler = {
            [self] (chunk: HandshakeChunk) async throws(QUICConnectionDriverError) in
            try await processHandshakeChunk(chunk)
        }
        try await connection.run(handshakeHandler: handler)
    }

    public var isEstablished: Bool {
        lifecycle.withLock { $0.handshakeOutputFlushed }
    }

    public var isClosed: Bool { connection.isClosed }

    public var activityGeneration: UInt64 {
        connection.activityGeneration
    }

    public func waitForActivity(
        after observedGeneration: UInt64,
        until deadline: MonotonicInstant? = nil
    ) async throws(TimeError) -> QUICActivityWaitResult {
        try await connection.waitForActivity(
            after: observedGeneration,
            until: deadline
        )
    }

    public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
        tls.withLock { $0.negotiatedApplicationProtocol }
    }

    public var currentDestinationConnectionID: ConnectionID {
        connection.currentDestinationConnectionID
    }

    public var peerCloseReason: ConnectionCloseInfo? {
        connection.peerCloseReason
    }

    public func openStream(bidirectional: Bool) throws(QUICEngineError) -> UInt64 {
        try connection.openStream(bidirectional: bidirectional)
    }

    public func writeStream(
        _ id: UInt64,
        data: borrowing [UInt8]
    ) async throws(QUICConnectionDriverError) {
        try await connection.writeStream(id, data: data)
    }

    public func readStream(_ id: UInt64) -> [UInt8]? {
        connection.readStream(id)
    }

    public func streamReadFinished(_ id: UInt64) -> Bool {
        connection.streamReadFinished(id)
    }

    public func finishStream(_ id: UInt64) async throws(QUICConnectionDriverError) {
        try await connection.finishStream(id)
    }

    public func resetStream(
        _ id: UInt64,
        errorCode: UInt64
    ) async throws(QUICConnectionDriverError) {
        try await connection.resetStream(id, errorCode: errorCode)
    }

    public func resetStreamAt(
        _ id: UInt64,
        errorCode: UInt64,
        reliableSize: UInt64
    ) async throws(QUICConnectionDriverError) {
        try await connection.resetStreamAt(
            id,
            errorCode: errorCode,
            reliableSize: reliableSize
        )
    }

    public func stopSending(
        _ id: UInt64,
        errorCode: UInt64
    ) async throws(QUICConnectionDriverError) {
        try await connection.stopSending(id, errorCode: errorCode)
    }

    public func sendDatagram(
        _ payload: borrowing [UInt8]
    ) async throws(QUICConnectionDriverError) {
        try await connection.sendDatagram(payload)
    }

    public func takeNewStreams() -> [UInt64] { connection.takeNewStreams() }
    public func takeReadableStreams() -> [UInt64] { connection.takeReadableStreams() }
    public func takeDatagrams() -> [[UInt8]] { connection.takeDatagrams() }

    public func close(
        errorCode: UInt64,
        reason: borrowing [UInt8],
        isApplicationError: Bool
    ) async throws(QUICConnectionDriverError) {
        try await connection.close(
            errorCode: errorCode,
            reason: reason,
            isApplicationError: isApplicationError
        )
    }

    private func processHandshakeChunk(
        _ chunk: HandshakeChunk
    ) async throws(QUICConnectionDriverError) {
        let inputLevel: QUICTLSHandshakeInputLevel
        switch chunk.level {
        case .initial: inputLevel = .initial
        case .handshake: inputLevel = .handshake
        case .zeroRTT, .application:
            throw .engine(
                .protocolViolation("post-handshake TLS data arrived on the initial handshake path")
            )
        }

        var transition: QUICTLSHandshakeTransition
        do throws(QUICTLSHandshakeError) {
            transition = try withTLS {
                (session: inout QUICTLSServerSession) throws(QUICTLSHandshakeError)
                    -> QUICTLSHandshakeTransition in
                try session.receiveStep(chunk.data.span, at: inputLevel)
            }
        } catch let error {
            throw .tls(error)
        }

        while true {
            switch consume transition {
            case .output(let output):
                try connection.applyTLSOutput(output)
                try await connection.flushNow()
                try applyPeerTransportParametersIfAvailable()
                if connection.isEstablished && tls.withLock({ $0.isEstablished }) {
                    let becameEstablished = lifecycle.withLock { state -> Bool in
                        guard !state.handshakeOutputFlushed else { return false }
                        state.handshakeOutputFlushed = true
                        return true
                    }
                    if becameEstablished { connection.notifyActivity() }
                }
                return

            case .suspended(let request):
                let response: TLS13CapabilityResponse
                do throws(QUICTLSCapabilityError) {
                    response = try await capabilities.response(to: request)
                } catch let error {
                    throw .tlsCapability(error)
                }
                guard QUICTLSCapabilityCorrelation.matches(
                    response: response,
                    request: request
                ) else {
                    throw .tlsCapability(.invalidResponse)
                }
                do throws(QUICTLSHandshakeError) {
                    transition = try withTLS {
                        (session: inout QUICTLSServerSession) throws(QUICTLSHandshakeError)
                            -> QUICTLSHandshakeTransition in
                        try session.resume(response)
                    }
                } catch let error {
                    throw .tls(error)
                }
            }
        }
    }

    private func applyPeerTransportParametersIfAvailable()
        throws(QUICConnectionDriverError)
    {
        let alreadyApplied = lifecycle.withLock { $0.peerTransportParametersApplied }
        guard !alreadyApplied else { return }
        guard let encoded = tls.withLock({ $0.receivedTransportParameters }) else {
            return
        }

        let parameters: TransportParametersCore
        do throws(TransportParameterCodecError) {
            parameters = try encoded.withBorrowedBytes { bytes throws(TransportParameterCodecError) in
                try TransportParameterCodecCore.decode(bytes)
            }
        } catch let error {
            throw .transportParameters(error)
        }
        do throws(QUICEngineError) {
            try connection.applyPeerTransportParameters(parameters)
        } catch let error {
            throw .engine(error)
        }
        lifecycle.withLock { $0.peerTransportParametersApplied = true }
    }

    private func withTLS<Result: ~Copyable>(
        _ body: (inout QUICTLSServerSession) throws(QUICTLSHandshakeError) -> Result
    ) throws(QUICTLSHandshakeError) -> Result {
        do {
            return try tls.withLock { session in
                try body(&session)
            }
        } catch let error as QUICTLSHandshakeError {
            throw error
        } catch {
            throw .invalidState
        }
    }
}

extension QUICServerConnection where Environment.Capabilities == NoExternalQUICTLSCapabilities {
    public convenience init(
        configuration: QUICConnectionEngineConfiguration,
        tlsSession: consuming QUICTLSServerSession,
        transport: Environment.Transport,
        timer: Environment.Timer,
        peer: IPSocketEndpoint
    ) throws(QUICConnectionDriverError) {
        try self.init(
            configuration: configuration,
            tlsSession: tlsSession,
            capabilityProvider: NoExternalQUICTLSCapabilities(),
            transport: transport,
            timer: timer,
            peer: peer
        )
    }
}
