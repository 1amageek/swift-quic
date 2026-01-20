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
/// - Anti-amplification limit enforcement (RFC 9000 Section 8.1)
public final class ManagedConnection: Sendable {
    // MARK: - Properties

    /// Connection handler (low-level orchestration)
    private let handler: QUICConnectionHandler

    /// Packet processor (encryption/decryption)
    private let packetProcessor: PacketProcessor

    /// TLS provider
    private let tlsProvider: any TLS13Provider

    /// Anti-amplification limiter (RFC 9000 Section 8.1)
    /// Servers must not send more than 3x bytes received until address is validated
    private let amplificationLimiter: AntiAmplificationLimiter

    /// Path validation manager for connection migration (RFC 9000 Section 9.3)
    private let pathValidationManager: PathValidationManager

    /// Connection ID manager for connection migration (RFC 9000 Section 9.5)
    private let connectionIDManager: ConnectionIDManager

    /// Internal state
    private let state: Mutex<ManagedConnectionState>

    /// State for stream read continuations
    private struct StreamContinuationsState: Sendable {
        var continuations: [UInt64: CheckedContinuation<Data, any Error>] = [:]
        /// Buffer for stream data received before read() is called
        var pendingData: [UInt64: [Data]] = [:]
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

    /// State for session ticket stream (lazy initialization pattern)
    private struct SessionTicketState: Sendable {
        var continuation: AsyncStream<NewSessionTicketInfo>.Continuation?
        var stream: AsyncStream<NewSessionTicketInfo>?
        var isShutdown: Bool = false
        /// Buffer for tickets that arrive before sessionTickets is accessed
        var pendingTickets: [NewSessionTicketInfo] = []
    }
    private let sessionTicketState: Mutex<SessionTicketState>

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
        self.amplificationLimiter = AntiAmplificationLimiter(isServer: role == .server)
        self.pathValidationManager = PathValidationManager()
        self.connectionIDManager = ConnectionIDManager(
            activeConnectionIDLimit: transportParameters.activeConnectionIDLimit
        )
        self.localAddress = localAddress
        self.remoteAddress = remoteAddress
        // For clients, original DCID is the initial destination CID
        // For servers, original DCID is the DCID from the client's Initial packet
        self.originalConnectionID = originalConnectionID ?? destinationConnectionID
        self.transportParameters = transportParameters
        var initialState = ManagedConnectionState(
            role: role,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        )
        initialState.currentRemoteAddress = remoteAddress
        self.state = Mutex(initialState)
        self.streamContinuationsState = Mutex(StreamContinuationsState())
        self.incomingStreamState = Mutex(IncomingStreamState())
        self.sessionTicketState = Mutex(SessionTicketState())

        // Set TLS provider on handler
        handler.setTLSProvider(tlsProvider)
    }

    // MARK: - Connection Lifecycle

    /// Starts the connection handshake
    /// - Returns: Initial packets to send (for client)
    public func start() async throws -> [Data] {
        // Prevent double-start: check and set state atomically
        let role = try state.withLock { s -> ConnectionRole in
            guard s.handshakeState == .idle else {
                throw ManagedConnectionError.invalidState("Handshake already started")
            }
            s.handshakeState = .connecting
            return s.role
        }

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

        // State was already set to connecting at the beginning of this method

        // Process TLS outputs
        return try await processTLSOutputs(outputs)
    }

    /// Starts the connection handshake with 0-RTT early data
    ///
    /// RFC 9001 Section 4.6.1: Client sends Initial + 0-RTT packets in first flight
    /// when resuming a session that supports early data.
    ///
    /// - Parameters:
    ///   - session: The cached session to use for resumption
    ///   - earlyData: Optional early data to send as 0-RTT
    /// - Returns: Tuple of (Initial packets, 0-RTT packets)
    public func startWith0RTT(
        session: ClientSessionCache.CachedSession,
        earlyData: Data?
    ) async throws -> (initialPackets: [Data], zeroRTTPackets: [Data]) {
        // Prevent double-start: check and set state atomically
        try state.withLock { s in
            guard s.handshakeState == .idle else {
                throw ManagedConnectionError.invalidState("Handshake already started")
            }
            guard s.role == .client else {
                throw QUICEarlyDataError.earlyDataNotSupported
            }
            s.handshakeState = .connecting
            s.is0RTTAttempted = true
        }

        // Derive initial keys using the original connection ID
        let (_, _) = try packetProcessor.deriveAndInstallInitialKeys(
            connectionID: originalConnectionID,
            isClient: true,
            version: handler.version
        )

        // Set transport parameters on TLS
        let encodedParams = encodeTransportParameters(transportParameters)
        try tlsProvider.setLocalTransportParameters(encodedParams)

        // Configure TLS for session resumption with 0-RTT
        // This must be done BEFORE startHandshake() so the ClientStateMachine
        // can derive 0-RTT keys using the correct ClientHello transcript hash
        try tlsProvider.configureResumption(
            ticket: session.sessionTicketData,
            attemptEarlyData: earlyData != nil
        )

        // Start TLS handshake (will include PSK extension for resumption)
        // The TLS provider will:
        // 1. Build ClientHello with PSK extension
        // 2. Derive early secret from PSK
        // 3. Compute ClientHello transcript hash
        // 4. Derive client_early_traffic_secret with correct transcript
        // 5. Return 0-RTT keys in the outputs
        let outputs = try await tlsProvider.startHandshake(isClient: true)

        // State was already set to connecting at the beginning of this method

        // Process TLS outputs (installs 0-RTT keys and generates Initial packets)
        let initialPackets = try await processTLSOutputs(outputs)

        // Generate 0-RTT packets with early data
        var zeroRTTPackets: [Data] = []
        if let data = earlyData, !data.isEmpty {
            // Open a stream for early data (stream ID 0 for client-initiated bidirectional)
            let streamID: UInt64 = 0
            handler.queueFrame(.stream(StreamFrame(
                streamID: streamID,
                offset: 0,
                data: data,
                fin: false
            )), level: .zeroRTT)

            // Generate 0-RTT packet
            let packets = try generate0RTTPackets()
            zeroRTTPackets.append(contentsOf: packets)
        }

        return (initialPackets, zeroRTTPackets)
    }

    /// Generates 0-RTT packets from queued frames
    private func generate0RTTPackets() throws -> [Data] {
        let outboundPackets = handler.getOutboundPackets()
        var result: [Data] = []

        for packet in outboundPackets where packet.level == .zeroRTT {
            let pn = handler.getNextPacketNumber(for: .zeroRTT)
            let header = build0RTTHeader(packetNumber: pn)

            let encrypted = try packetProcessor.encryptLongHeaderPacket(
                frames: packet.frames,
                header: header,
                packetNumber: pn,
                padToMinimum: false
            )
            result.append(encrypted)
        }

        return result
    }

    /// Builds a 0-RTT packet header
    private func build0RTTHeader(packetNumber: UInt64) -> LongHeader {
        let (scid, dcid) = state.withLock { ($0.sourceConnectionID, $0.destinationConnectionID) }
        return LongHeader(
            packetType: .zeroRTT,
            version: handler.version,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            packetNumber: packetNumber
        )
    }

    /// Processes an incoming packet
    /// - Parameter data: The encrypted packet data
    /// - Returns: Outbound packets to send in response
    public func processIncomingPacket(_ data: Data) async throws -> [Data] {
        // Record received bytes for anti-amplification limit
        amplificationLimiter.recordBytesReceived(UInt64(data.count))

        // Decrypt the packet
        let parsed = try packetProcessor.decryptPacket(data)

        // RFC 9000 Section 8.1: Server validates client address upon receiving Handshake packet
        if parsed.encryptionLevel == .handshake {
            amplificationLimiter.validateAddress()
        }

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

        // Apply anti-amplification limit
        return applyAmplificationLimit(to: outboundPackets)
    }

    /// Processes a coalesced datagram (multiple packets)
    /// - Parameter datagram: The UDP datagram
    /// - Returns: Outbound packets to send in response
    public func processDatagram(_ datagram: Data) async throws -> [Data] {
        // Record received bytes for anti-amplification limit
        amplificationLimiter.recordBytesReceived(UInt64(datagram.count))

        let parsedPackets = try packetProcessor.decryptDatagram(datagram)

        // RFC 9000 Section 6.2: Mark that we've received a valid packet
        // This prevents late Version Negotiation packets from being processed
        if !parsedPackets.isEmpty {
            state.withLock { $0.hasReceivedValidPacket = true }
        }

        var allOutbound: [Data] = []

        for parsed in parsedPackets {
            // RFC 9000 Section 8.1: Server validates client address upon receiving Handshake packet
            if parsed.encryptionLevel == .handshake {
                amplificationLimiter.validateAddress()
            }

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

        // Apply anti-amplification limit to outbound packets (servers only)
        return applyAmplificationLimit(to: allOutbound)
    }

    /// Applies the anti-amplification limit to outbound packets
    ///
    /// RFC 9000 Section 8.1: Before address validation, servers MUST NOT send
    /// more than 3 times the data received from the client.
    ///
    /// - Parameter packets: Packets to potentially send
    /// - Returns: Packets that fit within the amplification limit
    private func applyAmplificationLimit(to packets: [Data]) -> [Data] {
        var allowedPackets: [Data] = []

        for packet in packets {
            let packetSize = UInt64(packet.count)

            if amplificationLimiter.canSend(bytes: packetSize) {
                amplificationLimiter.recordBytesSent(packetSize)
                allowedPackets.append(packet)
            }
            // Packets that exceed the limit are dropped
            // They will be retransmitted once more data is received
        }

        return allowedPackets
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

                // RFC 9000 Section 8.1: Lift amplification limit when handshake is confirmed
                amplificationLimiter.confirmHandshake()

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

            case .alert(let alert):
                // TLS Alert received - for QUIC, this results in CONNECTION_CLOSE
                // with crypto error code (0x100 + alert code) per RFC 9001 Section 4.8
                // For now, we throw an error which will be handled by the caller
                throw TLSError.handshakeFailed(
                    alert: alert.alertDescription.rawValue,
                    description: alert.description
                )

            case .newSessionTicket(let ticketInfo):
                // RFC 8446 Section 4.6.1: NewSessionTicket received post-handshake
                // Store it for the client to use for future connections
                notifySessionTicketReceived(ticketInfo)
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
        for (streamID, data) in result.streamData {
            notifyStreamDataReceived(streamID, data: data)
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

    /// Notifies that data has been received on a stream
    ///
    /// Thread-safe: If a reader is waiting, resume it with the data.
    /// If no reader is waiting, buffer the data for later retrieval.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID
    ///   - data: The received data
    private func notifyStreamDataReceived(_ streamID: UInt64, data: Data) {
        streamContinuationsState.withLock { state in
            // Don't process if shutdown
            guard !state.isShutdown else { return }

            // If someone is waiting, resume them with the data
            if let continuation = state.continuations.removeValue(forKey: streamID) {
                continuation.resume(returning: data)
            } else {
                // No reader waiting - buffer the data for later
                state.pendingData[streamID, default: []].append(data)
            }
        }
    }

    // MARK: - Transport Parameters

    /// Encodes transport parameters to wire format using RFC 9000 compliant codec
    private func encodeTransportParameters(_ params: TransportParameters) -> Data {
        // Use proper TransportParameterCodec for RFC 9000 compliant encoding
        // This includes mandatory initial_source_connection_id parameter
        return TransportParameterCodec.encode(params)
    }

    /// Decodes transport parameters from wire format
    private func decodeTransportParameters(_ data: Data) -> TransportParameters? {
        // Use proper TransportParameterCodec for RFC 9000 compliant decoding
        return try? TransportParameterCodec.decode(data)
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

    /// Stream of session tickets received from the server
    ///
    /// Use this to receive `NewSessionTicket` messages for session resumption.
    /// Store these tickets in a `ClientSessionCache` for future 0-RTT connections.
    ///
    /// ## Usage
    /// ```swift
    /// let sessionCache = ClientSessionCache()
    /// Task {
    ///     for await ticketInfo in connection.sessionTickets {
    ///         sessionCache.storeTicket(
    ///             ticketInfo.ticket,
    ///             resumptionMasterSecret: ticketInfo.resumptionMasterSecret,
    ///             cipherSuite: ticketInfo.cipherSuite,
    ///             alpn: ticketInfo.alpn,
    ///             serverIdentity: "\(connection.remoteAddress)"
    ///         )
    ///     }
    /// }
    /// ```
    public var sessionTickets: AsyncStream<NewSessionTicketInfo> {
        sessionTicketState.withLock { state in
            // If shutdown, return existing finished stream or create a finished one
            if state.isShutdown {
                if let existing = state.stream { return existing }
                let (stream, continuation) = AsyncStream<NewSessionTicketInfo>.makeStream()
                continuation.finish()
                state.stream = stream
                return stream
            }

            // Return existing stream if already created
            if let existing = state.stream { return existing }

            // Create new stream
            let (stream, continuation) = AsyncStream<NewSessionTicketInfo>.makeStream()
            state.stream = stream
            state.continuation = continuation

            // Drain any pending tickets
            for pendingTicket in state.pendingTickets {
                continuation.yield(pendingTicket)
            }
            state.pendingTickets.removeAll()

            return stream
        }
    }

    /// Notifies that a session ticket was received (internal helper)
    private func notifySessionTicketReceived(_ ticketInfo: NewSessionTicketInfo) {
        sessionTicketState.withLock { state in
            guard !state.isShutdown else { return }

            if let continuation = state.continuation {
                // Stream is active, yield directly
                continuation.yield(ticketInfo)
            } else {
                // Buffer until sessionTickets is accessed
                state.pendingTickets.append(ticketInfo)
            }
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
        // Guard against concurrent calls - finish() is idempotent but we avoid duplicate work
        incomingStreamState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true  // Mark as shutdown FIRST
            state.continuation?.finish()
            state.continuation = nil
            state.pendingStreams.removeAll()  // Clear any buffered streams
            // DO NOT set stream = nil - existing iterators need it
        }

        // Finish session ticket stream and mark as shutdown
        sessionTicketState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true
            state.continuation?.finish()
            state.continuation = nil
            state.pendingTickets.removeAll()
        }

        // Resume any waiting stream readers with connection closed error
        // and mark as shutdown to prevent new readers from hanging
        streamContinuationsState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true  // Mark as shutdown FIRST
            for (_, continuation) in state.continuations {
                continuation.resume(throwing: ManagedConnectionError.connectionClosed)
            }
            state.continuations.removeAll()
        }

        // Finish send signal stream to stop outboundSendLoop in QUICEndpoint
        state.withLock { s in
            guard !s.isSendSignalShutdown else { return }  // Already shutdown
            s.isSendSignalShutdown = true
            s.sendSignalContinuation?.finish()
            s.sendSignalContinuation = nil
        }
    }
}

// MARK: - Internal Stream Access

extension ManagedConnection {
    /// Writes data to a stream (called by ManagedStream)
    func writeToStream(_ streamID: UInt64, data: Data) throws {
        try handler.writeToStream(streamID, data: data)
        signalNeedsSend()
    }

    /// Reads data from a stream (called by ManagedStream)
    ///
    /// Thread-safe: Prevents concurrent reads on the same stream.
    /// Only one reader can wait for data at a time per stream.
    /// Returns connectionClosed error if called after shutdown.
    ///
    /// Data sources (in priority order):
    /// 1. Pending data buffer (from processFrameResult)
    /// 2. Handler's stream buffer
    /// 3. Wait for data via continuation
    func readFromStream(_ streamID: UInt64) async throws -> Data {
        // Try to get data atomically - check buffer first, then handler
        return try await withCheckedThrowingContinuation { continuation in
            streamContinuationsState.withLock { state in
                // Check if shutdown
                guard !state.isShutdown else {
                    continuation.resume(throwing: ManagedConnectionError.connectionClosed)
                    return
                }

                // Priority 1: Check pending data buffer
                if var pending = state.pendingData[streamID], !pending.isEmpty {
                    let data = pending.removeFirst()
                    if pending.isEmpty {
                        state.pendingData.removeValue(forKey: streamID)
                    } else {
                        state.pendingData[streamID] = pending
                    }
                    continuation.resume(returning: data)
                    return
                }

                // Priority 2: Check handler's stream buffer
                if let data = handler.readFromStream(streamID) {
                    continuation.resume(returning: data)
                    return
                }

                // Priority 3: Wait for data
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
        signalNeedsSend()
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

// MARK: - Send Signal

extension ManagedConnection {
    /// Signal that packets need to be sent.
    ///
    /// QUICEndpoint monitors this stream and, upon receiving a signal,
    /// calls `generateOutboundPackets()` to send packets.
    ///
    /// Multiple writes before signal processing will be coalesced into
    /// a single packet generation (efficient batching via `bufferingNewest(1)`).
    ///
    /// ## Usage
    /// ```swift
    /// // In QUICEndpoint
    /// Task {
    ///     for await _ in connection.sendSignal {
    ///         let packets = try connection.generateOutboundPackets()
    ///         for packet in packets {
    ///             socket.send(packet, to: address)
    ///         }
    ///     }
    /// }
    /// ```
    public var sendSignal: AsyncStream<Void> {
        state.withLock { s in
            // After shutdown, return an already-finished stream
            if s.isSendSignalShutdown {
                if let existing = s.sendSignalStream { return existing }
                let (stream, continuation) = AsyncStream<Void>.makeStream(
                    bufferingPolicy: .bufferingNewest(1)
                )
                continuation.finish()
                s.sendSignalStream = stream
                return stream
            }

            // Return existing stream if already created (lazy initialization)
            if let existing = s.sendSignalStream { return existing }

            // Create new stream with bufferingNewest(1) for coalescing
            // Multiple yields before consumption result in only one signal
            let (stream, continuation) = AsyncStream<Void>.makeStream(
                bufferingPolicy: .bufferingNewest(1)
            )
            s.sendSignalStream = stream
            s.sendSignalContinuation = continuation
            return stream
        }
    }

    /// Notifies that packets need to be sent.
    ///
    /// Called after `writeToStream()` or `finishStream()` to trigger
    /// packet generation and transmission in QUICEndpoint.
    private func signalNeedsSend() {
        state.withLock { s in
            guard !s.isSendSignalShutdown else { return }
            s.sendSignalContinuation?.yield(())
        }
    }
}

// MARK: - Connection IDs

extension ManagedConnection {
    /// The TLS provider used for this connection.
    ///
    /// Provides access to the underlying TLS 1.3 provider for custom
    /// authentication schemes (e.g., libp2p certificate-based PeerID extraction).
    public var underlyingTLSProvider: any TLS13Provider {
        tlsProvider
    }

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

    // MARK: - Amplification Limit

    /// Whether the connection is blocked by the anti-amplification limit
    ///
    /// When blocked, the server must wait for more data from the client
    /// before it can send additional packets.
    public var isAmplificationBlocked: Bool {
        amplificationLimiter.isBlocked
    }

    /// Whether the client's address has been validated
    ///
    /// Address validation lifts the anti-amplification limit.
    public var isAddressValidated: Bool {
        amplificationLimiter.isAddressValidated
    }

    // MARK: - Version Negotiation

    /// Whether we have received and successfully processed any valid packet
    ///
    /// RFC 9000 Section 6.2: A client MUST discard any Version Negotiation packet
    /// if it has received and successfully processed any other packet.
    public var hasReceivedValidPacket: Bool {
        get async { state.withLock { $0.hasReceivedValidPacket } }
    }

    /// Retry the connection with a different QUIC version
    ///
    /// Called when a Version Negotiation packet is received offering a version we support.
    /// This resets the connection state and restarts the handshake with the new version.
    ///
    /// - Parameter version: The new version to use
    public func retryWithVersion(_ version: QUICVersion) async throws {
        // This is a complex operation that requires:
        // 1. Resetting TLS state
        // 2. Regenerating Initial keys with the new version
        // 3. Rebuilding and resending ClientHello
        // For now, throw an error indicating manual reconnection is needed
        throw QUICVersionError.versionNegotiationReceived(
            offeredVersions: [version]
        )
    }

    // MARK: - Connection Migration (RFC 9000 Section 9)

    /// The current remote address (may differ from initial address after migration)
    public var currentRemoteAddress: SocketAddress {
        state.withLock { $0.currentRemoteAddress ?? remoteAddress }
    }

    /// Whether the current path has been validated
    public var isPathValidated: Bool {
        state.withLock { $0.pathValidated }
    }

    /// Handles a packet received from a different address (potential migration)
    ///
    /// RFC 9000 Section 9.3: When receiving a packet from a new peer address,
    /// the endpoint MUST perform path validation if it has not previously done so.
    ///
    /// - Parameters:
    ///   - packet: The received packet data
    ///   - newAddress: The new remote address from which the packet was received
    /// - Returns: Packets to send in response (may include PATH_CHALLENGE)
    /// - Throws: `MigrationError` if migration is not allowed
    public func handleAddressChange(
        packet: Data,
        newAddress: SocketAddress
    ) async throws -> [Data] {
        // Check if migration is allowed
        let (allowMigration, currentAddress) = state.withLock { s in
            (
                !s.peerDisableActiveMigration,
                s.currentRemoteAddress ?? remoteAddress
            )
        }

        // If address hasn't changed, process normally
        if newAddress == currentAddress {
            return try await processIncomingPacket(packet)
        }

        // Check if peer allows migration
        guard allowMigration else {
            throw MigrationError.migrationDisabled
        }

        // Update address and mark path as not validated
        state.withLock { s in
            s.currentRemoteAddress = newAddress
            s.pathValidated = false
        }

        // For servers: reset anti-amplification limit for new path (RFC 9000 Section 9.3)
        // Note: Address validation needs to be completed via PATH_CHALLENGE/RESPONSE
        // The amplification limiter will be reset once path validation completes

        // Record bytes received for anti-amplification
        amplificationLimiter.recordBytesReceived(UInt64(packet.count))

        // Process the packet
        var responses = try await processIncomingPacket(packet)

        // Initiate path validation by sending PATH_CHALLENGE
        let path = NetworkPath(
            localAddress: localAddress?.description ?? "",
            remoteAddress: newAddress.description
        )
        let challengeData = pathValidationManager.startValidation(for: path)

        // Queue PATH_CHALLENGE to be sent with next packet
        state.withLock { s in
            s.pendingPathChallenges.append(challengeData)
        }

        // Generate a packet with PATH_CHALLENGE if we can
        if let challengePacket = try createPathChallengePacket(challengeData: challengeData) {
            responses.append(challengePacket)
        }

        return responses
    }

    /// Handles a PATH_CHALLENGE frame
    ///
    /// RFC 9000 Section 9.3.2: An endpoint MUST respond immediately to a
    /// PATH_CHALLENGE frame with a PATH_RESPONSE frame containing the same data.
    ///
    /// - Parameter data: The 8-byte challenge data
    /// - Returns: PATH_RESPONSE packet to send
    public func handlePathChallenge(_ data: Data) throws -> Data? {
        // Generate PATH_RESPONSE
        _ = pathValidationManager.handleChallenge(data)

        // Queue response to be sent
        state.withLock { s in
            s.pendingPathResponses.append(data)
        }

        // Create packet with PATH_RESPONSE
        return try createPathResponsePacket(data: data)
    }

    /// Handles a PATH_RESPONSE frame
    ///
    /// RFC 9000 Section 9.3.3: Receipt of a PATH_RESPONSE frame indicates
    /// that the path is valid.
    ///
    /// - Parameter data: The 8-byte response data
    /// - Returns: Whether this completes path validation
    public func handlePathResponse(_ data: Data) -> Bool {
        if let _ = pathValidationManager.handleResponse(data) {
            // Path validated successfully
            state.withLock { s in
                s.pathValidated = true
            }
            return true
        }
        return false
    }

    /// Sets whether peer allows active migration (from transport parameters)
    ///
    /// Called when processing peer's transport parameters.
    public func setPeerDisableActiveMigration(_ disabled: Bool) {
        state.withLock { s in
            s.peerDisableActiveMigration = disabled
        }
    }

    /// Gets pending PATH_CHALLENGE frames to include in next packet
    public func getPendingPathChallenges() -> [Data] {
        state.withLock { s in
            let challenges = s.pendingPathChallenges
            s.pendingPathChallenges.removeAll()
            return challenges
        }
    }

    /// Gets pending PATH_RESPONSE frames to include in next packet
    public func getPendingPathResponses() -> [Data] {
        state.withLock { s in
            let responses = s.pendingPathResponses
            s.pendingPathResponses.removeAll()
            return responses
        }
    }

    // MARK: - Migration Private Helpers

    /// Creates a packet containing a PATH_CHALLENGE frame
    ///
    /// - Note: This queues the frame to be sent with the next outbound packet.
    ///   The actual packet creation happens via the normal packet sending mechanism.
    private func createPathChallengePacket(challengeData: Data) throws -> Data? {
        // PATH_CHALLENGE will be included in the next 1-RTT packet
        // Queue the frame via the handler
        handler.queueFrame(.pathChallenge(challengeData), level: .application)

        // Return nil - the frame will be sent with normal packet flow
        // This avoids duplicating packet creation logic
        return nil
    }

    /// Creates a packet containing a PATH_RESPONSE frame
    ///
    /// - Note: This queues the frame to be sent with the next outbound packet.
    private func createPathResponsePacket(data: Data) throws -> Data? {
        // PATH_RESPONSE must be sent immediately (RFC 9000 Section 8.2.2)
        // Queue the frame via the handler
        handler.queueFrame(.pathResponse(data), level: .application)

        // Return nil - the frame will be sent with normal packet flow
        return nil
    }
}

/// Connection migration errors
public enum MigrationError: Error, Sendable {
    /// Migration is disabled by peer (disable_active_migration transport parameter)
    case migrationDisabled

    /// Path validation failed
    case pathValidationFailed(reason: String)

    /// No active connection ID available for migration
    case noActiveConnectionID
}

// MARK: - Internal State

private struct ManagedConnectionState: Sendable {
    var role: ConnectionRole
    var handshakeState: HandshakeState = .idle
    var sourceConnectionID: ConnectionID
    var destinationConnectionID: ConnectionID
    var negotiatedALPN: String? = nil
    /// Whether 0-RTT was attempted in this connection
    var is0RTTAttempted: Bool = false
    /// Whether 0-RTT was accepted by server (set after receiving EncryptedExtensions)
    var is0RTTAccepted: Bool = false
    /// Whether we have received and successfully processed any valid packet
    /// RFC 9000 Section 6.2: Used to discard late Version Negotiation packets
    var hasReceivedValidPacket: Bool = false

    // MARK: - Connection Migration State

    /// Current remote address (may change during connection migration)
    var currentRemoteAddress: SocketAddress?

    /// Whether the current path has been validated (RFC 9000 Section 9.3)
    var pathValidated: Bool = true

    /// Whether peer allows active migration (from transport parameters)
    var peerDisableActiveMigration: Bool = false

    /// Pending PATH_CHALLENGE frames to send
    var pendingPathChallenges: [Data] = []

    /// Pending PATH_RESPONSE frames to send
    var pendingPathResponses: [Data] = []

    // MARK: - Send Signal State

    /// Continuation for send signal stream
    var sendSignalContinuation: AsyncStream<Void>.Continuation?

    /// Send signal stream (lazily initialized)
    var sendSignalStream: AsyncStream<Void>?

    /// Whether send signal has been shutdown
    var isSendSignalShutdown: Bool = false
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
