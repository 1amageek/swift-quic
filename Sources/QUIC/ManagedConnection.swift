/// Managed Connection
///
/// High-level connection wrapper that orchestrates handshake, packet processing,
/// and stream management. Implements QUICConnectionProtocol for public API.

import Foundation
import Synchronization
import QUICCore
import QUICCrypto
import QUICConnection
import QUICStream
import QUICRecovery

// MARK: - Handshake State

/// Connection handshake state
public enum HandshakeState: Sendable, Equatable {
    /// Connection not yet started
    case idle

    /// Client: Initial packet sent, waiting for server response
    /// Server: Not applicable
    case connecting

    /// Server: Initial received, handshake in progress
    /// Client: Handshake packets being exchanged
    case handshakeInProgress

    /// Handshake complete, connection established
    case established

    /// Connection is closing
    case closing

    /// Connection is closed
    case closed
}

// MARK: - Managed Connection

/// High-level managed connection for QUIC
///
/// Wraps QUICConnectionHandler and provides:
/// - Handshake state machine
/// - Packet encryption/decryption via PacketProcessor
/// - TLS 1.3 integration
/// - Stream management via QUICConnectionProtocol
public final class ManagedConnection: Sendable {
    // MARK: - Properties

    /// Connection handler (low-level orchestration)
    private let handler: QUICConnectionHandler

    /// Packet processor (encryption/decryption)
    private let packetProcessor: PacketProcessor

    /// TLS provider
    private let tlsProvider: any TLS13Provider

    /// Internal state
    private let state: Mutex<ManagedConnectionState>

    /// State for stream read continuations
    private struct StreamContinuationsState: Sendable {
        var continuations: [UInt64: CheckedContinuation<Data, any Error>] = [:]
        var isShutdown: Bool = false
    }

    /// Stream continuations for async stream API
    private let streamContinuationsState: Mutex<StreamContinuationsState>

    /// State for incoming stream AsyncStream (lazy initialization pattern)
    private struct IncomingStreamState: Sendable {
        var continuation: AsyncStream<any QUICStreamProtocol>.Continuation?
        var stream: AsyncStream<any QUICStreamProtocol>?
        var isShutdown: Bool = false
        /// Buffer for streams that arrive before incomingStreams is accessed
        var pendingStreams: [any QUICStreamProtocol] = []
    }
    private let incomingStreamState: Mutex<IncomingStreamState>

    /// Original connection ID (for Initial key derivation)
    /// This is the DCID from the first client Initial packet
    private let originalConnectionID: ConnectionID

    /// Transport parameters (stored for TLS)
    private let transportParameters: TransportParameters

    /// Local address
    public let localAddress: SocketAddress?

    /// Remote address
    public let remoteAddress: SocketAddress

    // MARK: - Initialization

    /// Creates a new managed connection
    /// - Parameters:
    ///   - role: Connection role (client or server)
    ///   - version: QUIC version
    ///   - sourceConnectionID: Local connection ID
    ///   - destinationConnectionID: Remote connection ID
    ///   - originalConnectionID: Original DCID for Initial key derivation (defaults to destinationConnectionID)
    ///   - transportParameters: Transport parameters to use
    ///   - tlsProvider: TLS 1.3 provider
    ///   - localAddress: Local socket address (optional)
    ///   - remoteAddress: Remote socket address
    public init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID,
        originalConnectionID: ConnectionID? = nil,
        transportParameters: TransportParameters,
        tlsProvider: any TLS13Provider,
        localAddress: SocketAddress? = nil,
        remoteAddress: SocketAddress
    ) {
        self.handler = QUICConnectionHandler(
            role: role,
            version: version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID,
            transportParameters: transportParameters
        )
        self.packetProcessor = PacketProcessor(dcidLength: sourceConnectionID.length)
        self.tlsProvider = tlsProvider
        self.localAddress = localAddress
        self.remoteAddress = remoteAddress
        // For clients, original DCID is the initial destination CID
        // For servers, original DCID is the DCID from the client's Initial packet
        self.originalConnectionID = originalConnectionID ?? destinationConnectionID
        self.transportParameters = transportParameters
        self.state = Mutex(ManagedConnectionState(
            role: role,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        ))
        self.streamContinuationsState = Mutex(StreamContinuationsState())
        self.incomingStreamState = Mutex(IncomingStreamState())

        // Set TLS provider on handler
        handler.setTLSProvider(tlsProvider)
    }

    // MARK: - Connection Lifecycle

    /// Starts the connection handshake
    /// - Returns: Initial packets to send (for client)
    public func start() async throws -> [Data] {
        let role = state.withLock { $0.role }

        // Derive initial keys using the original connection ID
        // RFC 9001: Both client and server derive Initial keys from the
        // Destination Connection ID in the first Initial packet sent by the client
        // PacketProcessor is the single source of truth for crypto contexts
        let (_, _) = try packetProcessor.deriveAndInstallInitialKeys(
            connectionID: originalConnectionID,
            isClient: role == .client,
            version: handler.version
        )

        // Set transport parameters on TLS (use the stored parameters)
        let encodedParams = encodeTransportParameters(transportParameters)
        try tlsProvider.setLocalTransportParameters(encodedParams)

        // Start TLS handshake
        let outputs = try await tlsProvider.startHandshake(isClient: role == .client)

        state.withLock { $0.handshakeState = .connecting }

        // Process TLS outputs
        return try await processTLSOutputs(outputs)
    }

    /// Processes an incoming packet
    /// - Parameter data: The encrypted packet data
    /// - Returns: Outbound packets to send in response
    public func processIncomingPacket(_ data: Data) async throws -> [Data] {
        // Decrypt the packet
        let parsed = try packetProcessor.decryptPacket(data)

        // Record received packet
        handler.recordReceivedPacket(
            packetNumber: parsed.packetNumber,
            level: parsed.encryptionLevel,
            isAckEliciting: parsed.frames.contains { $0.isAckEliciting },
            receiveTime: .now
        )

        // Process frames
        let result = try handler.processFrames(parsed.frames, level: parsed.encryptionLevel)

        // Handle frame results (common logic)
        var outboundPackets = try await processFrameResult(result)

        // Generate response packets (ACKs, etc.)
        let responsePackets = try generateOutboundPackets()
        outboundPackets.append(contentsOf: responsePackets)

        return outboundPackets
    }

    /// Processes a coalesced datagram (multiple packets)
    /// - Parameter datagram: The UDP datagram
    /// - Returns: Outbound packets to send in response
    public func processDatagram(_ datagram: Data) async throws -> [Data] {
        let parsedPackets = try packetProcessor.decryptDatagram(datagram)

        var allOutbound: [Data] = []

        for parsed in parsedPackets {
            // Record received packet
            handler.recordReceivedPacket(
                packetNumber: parsed.packetNumber,
                level: parsed.encryptionLevel,
                isAckEliciting: parsed.frames.contains { $0.isAckEliciting },
                receiveTime: .now
            )

            // Process frames
            let result = try handler.processFrames(parsed.frames, level: parsed.encryptionLevel)

            // Handle frame results (common logic)
            let outbound = try await processFrameResult(result)
            allOutbound.append(contentsOf: outbound)
        }

        // Generate response packets
        let responsePackets = try generateOutboundPackets()
        allOutbound.append(contentsOf: responsePackets)

        return allOutbound
    }

    /// Generates outbound packets ready to send
    /// - Returns: Array of encrypted packet data
    public func generateOutboundPackets() throws -> [Data] {
        let outboundPackets = handler.getOutboundPackets()
        var result: [Data] = []

        // Group packets by level for coalescing
        var packetsByLevel: [EncryptionLevel: [(frames: [Frame], header: PacketHeader, packetNumber: UInt64)]] = [:]

        for packet in outboundPackets {
            let pn = handler.getNextPacketNumber(for: packet.level)
            let header = buildPacketHeader(for: packet.level, packetNumber: pn)

            packetsByLevel[packet.level, default: []].append((
                frames: packet.frames,
                header: header,
                packetNumber: pn
            ))
        }

        // Try to coalesce Initial + Handshake packets
        let hasInitial = packetsByLevel[.initial] != nil
        let hasHandshake = packetsByLevel[.handshake] != nil

        if hasInitial {
            // Build Initial packets (will be padded to 1200 bytes)
            for packet in packetsByLevel[.initial]! {
                if case .long(let longHeader) = packet.header {
                    let encrypted = try packetProcessor.encryptLongHeaderPacket(
                        frames: packet.frames,
                        header: longHeader,
                        packetNumber: packet.packetNumber,
                        padToMinimum: true
                    )
                    result.append(encrypted)
                }
            }
        }

        if hasHandshake {
            // Build Handshake packets separately
            // (Can't coalesce with Initial since Initial is padded to 1200)
            for packet in packetsByLevel[.handshake]! {
                if case .long(let longHeader) = packet.header {
                    let encrypted = try packetProcessor.encryptLongHeaderPacket(
                        frames: packet.frames,
                        header: longHeader,
                        packetNumber: packet.packetNumber,
                        padToMinimum: false
                    )
                    result.append(encrypted)
                }
            }
        }

        // Build 1-RTT packets separately (they shouldn't be coalesced with Initial/Handshake)
        if let appPackets = packetsByLevel[.application] {
            for packet in appPackets {
                if case .short(let shortHeader) = packet.header {
                    let encrypted = try packetProcessor.encryptShortHeaderPacket(
                        frames: packet.frames,
                        header: shortHeader,
                        packetNumber: packet.packetNumber
                    )
                    result.append(encrypted)
                }
            }
        }

        return result
    }

    /// Called when a timer expires
    /// - Returns: Packets to send (probes, retransmits)
    public func onTimerExpired() throws -> [Data] {
        let action = handler.onTimerExpired()

        switch action {
        case .none:
            return []

        case .retransmit(_, let level):
            // SentPacket doesn't contain frame data, so we send a PING as probe
            // The actual retransmission is handled by the stream manager when
            // data hasn't been ACKed
            handler.queueFrame(.ping, level: level)
            return try generateOutboundPackets()

        case .probe:
            // Send a PING to probe
            let level: EncryptionLevel = isEstablished ? .application : .initial
            handler.queueFrame(.ping, level: level)
            return try generateOutboundPackets()
        }
    }

    /// Gets the next timer deadline
    public func nextTimerDeadline() -> ContinuousClock.Instant? {
        handler.nextTimerDeadline()
    }

    // MARK: - Handshake Helpers

    /// Processes TLS outputs and generates packets
    private func processTLSOutputs(_ outputs: [TLSOutput]) async throws -> [Data] {
        var outboundPackets: [Data] = []
        var handshakeCompleted = false

        for output in outputs {
            switch output {
            case .handshakeData(let data, let level):
                // Queue CRYPTO frames
                handler.queueCryptoData(data, level: level)

            case .keysAvailable(let info):
                // Install keys via PacketProcessor (single source of truth for crypto)
                let isClient = state.withLock { $0.role == .client }
                try packetProcessor.installKeys(info, isClient: isClient)

            case .handshakeComplete(let info):
                state.withLock { $0.negotiatedALPN = info.alpn }

                // Parse peer transport parameters
                if let peerParams = tlsProvider.getPeerTransportParameters() {
                    if let params = decodeTransportParameters(peerParams) {
                        handler.setPeerTransportParameters(params)
                    }
                }

                // Server: Send HANDSHAKE_DONE
                let role = state.withLock { $0.role }
                if role == .server {
                    handler.queueFrame(.handshakeDone, level: .application)
                }

                // Mark handshake as established but don't discard keys yet
                // We need to generate packets first
                state.withLock { $0.handshakeState = .established }
                handshakeCompleted = true

            case .needMoreData:
                // Wait for more data
                break

            case .error(let error):
                throw error
            }
        }

        // Generate packets from queued frames (BEFORE discarding keys)
        let packets = try generateOutboundPackets()
        outboundPackets.append(contentsOf: packets)

        // Discard Initial and Handshake keys if handshake completed
        // RFC 9001 Section 4.9.2:
        // - Server: Discard when TLS handshake completes (here)
        // - Client: Discard when HANDSHAKE_DONE is received (in completeHandshake)
        if handshakeCompleted {
            let role = state.withLock { $0.role }
            if role == .server {
                // Server discards keys immediately after handshake completes
                packetProcessor.discardKeys(for: .initial)
                packetProcessor.discardKeys(for: .handshake)
                handler.discardLevel(.initial)
                handler.discardLevel(.handshake)
            }
            // Client waits for HANDSHAKE_DONE before discarding keys
        }

        return outboundPackets
    }

    /// Completes the handshake (called when HANDSHAKE_DONE frame is received)
    ///
    /// RFC 9001 Section 4.9.2:
    /// - Server: Already discarded keys in processTLSOutputs()
    /// - Client: Discards keys here when HANDSHAKE_DONE is received
    private func completeHandshake() throws {
        // Single lock acquisition to get role and update state
        let role = state.withLock { s in
            s.handshakeState = .established
            return s.role
        }

        // Client discards keys when HANDSHAKE_DONE is received (RFC 9001 compliance)
        if role == .client {
            packetProcessor.discardKeys(for: .initial)
            packetProcessor.discardKeys(for: .handshake)
            handler.discardLevel(.initial)
            handler.discardLevel(.handshake)
        }
        // Server already discarded keys in processTLSOutputs()
    }

    /// Processes frame processing result (common logic for packet handling)
    ///
    /// Handles:
    /// - Crypto data (TLS messages)
    /// - New peer-initiated streams
    /// - Stream data notifications
    /// - Handshake completion
    /// - Connection close
    ///
    /// - Parameter result: The frame processing result
    /// - Returns: Outbound packets generated from TLS processing
    private func processFrameResult(_ result: FrameProcessingResult) async throws -> [Data] {
        var outboundPackets: [Data] = []

        // Handle crypto data (TLS messages)
        for (level, cryptoData) in result.cryptoData {
            let tlsOutputs = try await tlsProvider.processHandshakeData(cryptoData, at: level)
            let packets = try await processTLSOutputs(tlsOutputs)
            outboundPackets.append(contentsOf: packets)
        }

        // Handle new peer-initiated streams
        for streamID in result.newStreams {
            let isBidirectional = StreamID.isBidirectional(streamID)
            let stream = ManagedStream(
                id: streamID,
                connection: self,
                isUnidirectional: !isBidirectional
            )
            incomingStreamState.withLock { state in
                // Don't yield if shutdown
                guard !state.isShutdown else { return }

                if let continuation = state.continuation {
                    // Continuation exists, yield directly
                    continuation.yield(stream)
                } else {
                    // Buffer the stream until incomingStreams is accessed
                    state.pendingStreams.append(stream)
                }
            }
        }

        // Handle stream data
        for (streamID, _) in result.streamData {
            notifyStreamDataAvailable(streamID)
        }

        // Handle handshake completion (from HANDSHAKE_DONE frame)
        if result.handshakeComplete {
            try completeHandshake()
        }

        // Handle connection close
        if result.connectionClosed {
            state.withLock { $0.handshakeState = .closed }
            shutdown()  // Finish async streams to prevent hanging for-await loops
        }

        return outboundPackets
    }

    /// Builds a packet header for the given level
    private func buildPacketHeader(for level: EncryptionLevel, packetNumber: UInt64) -> PacketHeader {
        let (scid, dcid, version) = state.withLock { state in
            (state.sourceConnectionID, state.destinationConnectionID, handler.version)
        }

        switch level {
        case .initial:
            let longHeader = LongHeader(
                packetType: .initial,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: nil
            )
            return .long(longHeader)

        case .handshake:
            let longHeader = LongHeader(
                packetType: .handshake,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: nil
            )
            return .long(longHeader)

        case .application:
            let shortHeader = ShortHeader(
                destinationConnectionID: dcid,
                spinBit: false,
                keyPhase: false
            )
            return .short(shortHeader)

        default:
            // 0-RTT or other
            let longHeader = LongHeader(
                packetType: .zeroRTT,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: nil
            )
            return .long(longHeader)
        }
    }

    // MARK: - Stream Helpers

    /// Notifies that data is available on a stream
    ///
    /// Thread-safe: Only consumes data if a reader is waiting.
    /// If no reader is waiting, data stays in handler's buffer for later retrieval.
    private func notifyStreamDataAvailable(_ streamID: UInt64) {
        streamContinuationsState.withLock { state in
            // Don't process if shutdown
            guard !state.isShutdown else { return }

            // First check if someone is waiting - don't consume data otherwise
            guard let continuation = state.continuations.removeValue(forKey: streamID) else {
                // No reader waiting - data stays in handler's buffer
                // Reader will get it via fast path in readFromStream()
                return
            }

            // Now safe to consume the data
            if let data = handler.readFromStream(streamID) {
                continuation.resume(returning: data)
            } else {
                // Unexpected: notification without data - put continuation back
                state.continuations[streamID] = continuation
            }
        }
    }

    // MARK: - Transport Parameters

    /// Encodes transport parameters to wire format
    private func encodeTransportParameters(_ params: TransportParameters) -> Data {
        // Simple encoding - in production use proper varint encoding
        var data = Data()

        // Encode key parameters as TLV
        func appendParameter(id: UInt64, value: UInt64) {
            var idData = Data()
            Varint(id).encode(to: &idData)
            var valData = Data()
            Varint(value).encode(to: &valData)
            var lenData = Data()
            Varint(UInt64(valData.count)).encode(to: &lenData)
            data.append(idData)
            data.append(lenData)
            data.append(valData)
        }

        appendParameter(id: 0x04, value: params.initialMaxData)
        appendParameter(id: 0x05, value: params.initialMaxStreamDataBidiLocal)
        appendParameter(id: 0x06, value: params.initialMaxStreamDataBidiRemote)
        appendParameter(id: 0x07, value: params.initialMaxStreamDataUni)
        appendParameter(id: 0x08, value: params.initialMaxStreamsBidi)
        appendParameter(id: 0x09, value: params.initialMaxStreamsUni)

        return data
    }

    /// Decodes transport parameters from wire format
    private func decodeTransportParameters(_ data: Data) -> TransportParameters? {
        // For mock TLS, just return defaults
        // Real implementation would parse the TLV format
        return TransportParameters()
    }
}

// MARK: - QUICConnectionProtocol

extension ManagedConnection: QUICConnectionProtocol {
    public var isEstablished: Bool {
        state.withLock { $0.handshakeState == .established }
    }

    public func openStream() async throws -> any QUICStreamProtocol {
        let streamID = try handler.openStream(bidirectional: true)
        return ManagedStream(
            id: streamID,
            connection: self,
            isUnidirectional: false
        )
    }

    public func openUniStream() async throws -> any QUICStreamProtocol {
        let streamID = try handler.openStream(bidirectional: false)
        return ManagedStream(
            id: streamID,
            connection: self,
            isUnidirectional: true
        )
    }

    public func acceptStream() async throws -> any QUICStreamProtocol {
        // Wait for incoming stream via AsyncStream
        for await stream in incomingStreams {
            return stream
        }
        throw ManagedConnectionError.connectionClosed
    }

    public var incomingStreams: AsyncStream<any QUICStreamProtocol> {
        incomingStreamState.withLock { state in
            // If shutdown, return existing finished stream or create a finished one
            // This prevents new iterators from hanging after shutdown
            if state.isShutdown {
                if let existing = state.stream { return existing }
                // Create an already-finished stream
                let (stream, continuation) = AsyncStream<any QUICStreamProtocol>.makeStream()
                continuation.finish()
                state.stream = stream
                return stream
            }

            // Return existing stream if already created (lazy initialization)
            if let existing = state.stream { return existing }

            // Create new stream using makeStream() pattern (per coding guidelines)
            let (stream, continuation) = AsyncStream<any QUICStreamProtocol>.makeStream()
            state.stream = stream
            state.continuation = continuation

            // Drain any pending streams that arrived before this was accessed
            for pendingStream in state.pendingStreams {
                continuation.yield(pendingStream)
            }
            state.pendingStreams.removeAll()

            return stream
        }
    }

    public func close(error: UInt64?) async {
        handler.close(error: error.map { ConnectionCloseError(code: $0) })
        state.withLock { $0.handshakeState = .closing }
        shutdown()
    }

    public func close(applicationError errorCode: UInt64, reason: String) async {
        handler.close(error: ConnectionCloseError(code: errorCode, reason: reason))
        state.withLock { $0.handshakeState = .closing }
        shutdown()
    }

    /// Shuts down the connection and finishes all async streams
    ///
    /// This is required per coding guidelines: AsyncStream services MUST
    /// call continuation.finish() to prevent for-await loops from hanging.
    ///
    /// Note: We set isShutdown=true but keep the stream reference.
    /// This allows existing iterators to complete normally while preventing
    /// new iterators from hanging (they get an already-finished stream).
    public func shutdown() {
        // Finish incoming stream continuation and mark as shutdown
        incomingStreamState.withLock { state in
            state.isShutdown = true  // Mark as shutdown FIRST
            state.continuation?.finish()
            state.continuation = nil
            state.pendingStreams.removeAll()  // Clear any buffered streams
            // DO NOT set stream = nil - existing iterators need it
        }

        // Resume any waiting stream readers with connection closed error
        // and mark as shutdown to prevent new readers from hanging
        streamContinuationsState.withLock { state in
            state.isShutdown = true  // Mark as shutdown FIRST
            for (_, continuation) in state.continuations {
                continuation.resume(throwing: ManagedConnectionError.connectionClosed)
            }
            state.continuations.removeAll()
        }
    }
}

// MARK: - Internal Stream Access

extension ManagedConnection {
    /// Writes data to a stream (called by ManagedStream)
    func writeToStream(_ streamID: UInt64, data: Data) throws {
        try handler.writeToStream(streamID, data: data)
    }

    /// Reads data from a stream (called by ManagedStream)
    ///
    /// Thread-safe: Prevents concurrent reads on the same stream.
    /// Only one reader can wait for data at a time per stream.
    /// Returns connectionClosed error if called after shutdown.
    func readFromStream(_ streamID: UInt64) async throws -> Data {
        // Fast path: data already available
        if let data = handler.readFromStream(streamID) {
            return data
        }

        // Slow path: wait for data notification
        return try await withCheckedThrowingContinuation { continuation in
            streamContinuationsState.withLock { state in
                // Check if shutdown - must be inside lock to avoid race
                guard !state.isShutdown else {
                    continuation.resume(throwing: ManagedConnectionError.connectionClosed)
                    return
                }
                // Double-check: data may have arrived while acquiring lock
                if let data = handler.readFromStream(streamID) {
                    continuation.resume(returning: data)
                    return
                }
                // Prevent concurrent reads on the same stream
                guard state.continuations[streamID] == nil else {
                    continuation.resume(throwing: ManagedConnectionError.invalidState("Concurrent read on stream \(streamID)"))
                    return
                }
                state.continuations[streamID] = continuation
            }
        }
    }

    /// Finishes a stream (sends FIN)
    func finishStream(_ streamID: UInt64) throws {
        try handler.finishStream(streamID)
    }

    /// Resets a stream
    func resetStream(_ streamID: UInt64, errorCode: UInt64) {
        handler.closeStream(streamID)
    }

    /// Stops sending on a stream
    func stopSending(_ streamID: UInt64, errorCode: UInt64) {
        // Handler will generate STOP_SENDING frame
        handler.closeStream(streamID)
    }
}

// MARK: - Connection IDs

extension ManagedConnection {
    /// Source connection ID
    public var sourceConnectionID: ConnectionID {
        state.withLock { $0.sourceConnectionID }
    }

    /// Destination connection ID
    public var destinationConnectionID: ConnectionID {
        state.withLock { $0.destinationConnectionID }
    }

    /// Current handshake state
    public var handshakeState: HandshakeState {
        state.withLock { $0.handshakeState }
    }

    /// Connection role
    public var role: ConnectionRole {
        state.withLock { $0.role }
    }

    // Note: Connection ID tracking is now managed by ConnectionRouter.
    // Use router.registeredConnectionIDs(for:) to query CIDs for a connection.
}

// MARK: - Internal State

private struct ManagedConnectionState: Sendable {
    var role: ConnectionRole
    var handshakeState: HandshakeState = .idle
    var sourceConnectionID: ConnectionID
    var destinationConnectionID: ConnectionID
    var negotiatedALPN: String? = nil
}

// MARK: - Errors

/// Errors from ManagedConnection
public enum ManagedConnectionError: Error, Sendable {
    /// Connection is closed
    case connectionClosed

    /// Handshake not complete
    case handshakeNotComplete

    /// Stream not found
    case streamNotFound(UInt64)

    /// Invalid state
    case invalidState(String)
}
