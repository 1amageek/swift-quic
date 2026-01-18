/// QUIC Connection Handler
///
/// Main orchestrator for QUIC connection management.
/// Handles packet processing, loss detection, ACK generation,
/// and TLS handshake coordination.

import Foundation
import Synchronization
import QUICCore
import QUICRecovery
import QUICCrypto
import QUICStream

// MARK: - Connection Handler

/// Main handler for a QUIC connection
///
/// Orchestrates all connection components:
/// - Packet reception and transmission
/// - Loss detection and recovery
/// - ACK generation and processing
/// - TLS handshake coordination
/// - Key schedule management
public final class QUICConnectionHandler: Sendable {
    // MARK: - Properties

    /// Connection state
    private let connectionState: Mutex<ConnectionState>

    /// Packet number space manager (loss detection + ACK management)
    private let pnSpaceManager: PacketNumberSpaceManager

    /// Congestion controller
    private let congestionController: NewRenoCongestionController

    /// Crypto stream manager
    private let cryptoStreamManager: CryptoStreamManager

    /// Data stream manager
    private let streamManager: StreamManager

    /// Key schedule
    private let keySchedule: Mutex<KeySchedule>

    /// TLS provider (optional - can be set later)
    private let tlsProvider: Mutex<(any TLS13Provider)?> = Mutex(nil)

    /// Local transport parameters
    private let localTransportParams: TransportParameters

    /// Peer transport parameters (set after handshake)
    private let peerTransportParams: Mutex<TransportParameters?> = Mutex(nil)

    /// Crypto contexts for each encryption level
    private let cryptoContexts: Mutex<[EncryptionLevel: CryptoContext]>

    /// Pending outbound packets
    private let outboundQueue: Mutex<[OutboundPacket]> = Mutex([])

    /// Whether handshake is complete
    private let handshakeComplete: Mutex<Bool> = Mutex(false)

    // MARK: - Initialization

    /// Creates a new connection handler
    /// - Parameters:
    ///   - role: Connection role (client or server)
    ///   - version: QUIC version
    ///   - sourceConnectionID: Local connection ID
    ///   - destinationConnectionID: Peer's connection ID
    ///   - transportParameters: Local transport parameters
    public init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID,
        transportParameters: TransportParameters
    ) {
        self.connectionState = Mutex(ConnectionState(
            role: role,
            version: version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        ))

        self.pnSpaceManager = PacketNumberSpaceManager()
        self.congestionController = NewRenoCongestionController()
        self.cryptoStreamManager = CryptoStreamManager()

        // Initialize stream manager with transport parameters
        self.streamManager = StreamManager(
            isClient: role == .client,
            initialMaxData: transportParameters.initialMaxData,
            initialMaxStreamDataBidiLocal: transportParameters.initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote: transportParameters.initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni: transportParameters.initialMaxStreamDataUni,
            initialMaxStreamsBidi: transportParameters.initialMaxStreamsBidi,
            initialMaxStreamsUni: transportParameters.initialMaxStreamsUni
        )

        self.keySchedule = Mutex(KeySchedule())
        self.localTransportParams = transportParameters
        self.cryptoContexts = Mutex([:])
    }

    // MARK: - TLS Provider

    /// Sets the TLS provider for this connection
    /// - Parameter provider: The TLS 1.3 provider to use
    public func setTLSProvider(_ provider: any TLS13Provider) {
        tlsProvider.withLock { $0 = provider }
    }

    // MARK: - Initial Key Derivation

    /// Derives and installs initial keys
    /// - Parameter connectionID: The connection ID to use for key derivation.
    ///   If nil, uses the current destination connection ID. Servers should pass
    ///   the original DCID from the client's first Initial packet.
    /// - Returns: Tuple of client and server key material
    public func deriveInitialKeys(connectionID: ConnectionID? = nil) throws -> (client: KeyMaterial, server: KeyMaterial) {
        let (defaultCID, version) = connectionState.withLock { state in
            (state.currentDestinationCID, state.version)
        }
        let cid = connectionID ?? defaultCID

        let (clientKeys, serverKeys) = try keySchedule.withLock { schedule in
            try schedule.deriveInitialKeys(connectionID: cid, version: version)
        }

        // Create and install crypto contexts
        let role = connectionState.withLock { $0.role }
        let (readKeys, writeKeys) = role == .client ?
            (serverKeys, clientKeys) : (clientKeys, serverKeys)

        let opener = try AES128GCMOpener(keyMaterial: readKeys)
        let sealer = try AES128GCMSealer(keyMaterial: writeKeys)

        cryptoContexts.withLock { contexts in
            contexts[.initial] = CryptoContext(opener: opener, sealer: sealer)
        }

        return (client: clientKeys, server: serverKeys)
    }

    // MARK: - Packet Reception

    /// Records a received packet for ACK tracking
    /// - Parameters:
    ///   - packetNumber: The packet number
    ///   - level: The encryption level
    ///   - isAckEliciting: Whether the packet is ACK-eliciting
    ///   - receiveTime: When the packet was received
    public func recordReceivedPacket(
        packetNumber: UInt64,
        level: EncryptionLevel,
        isAckEliciting: Bool,
        receiveTime: ContinuousClock.Instant = .now
    ) {
        pnSpaceManager.onPacketReceived(
            packetNumber: packetNumber,
            level: level,
            isAckEliciting: isAckEliciting,
            receiveTime: receiveTime
        )

        // Update connection state
        connectionState.withLock { state in
            state.updateLargestReceived(packetNumber, level: level)
        }
    }

    // MARK: - Frame Processing

    /// Processes frames from a decrypted packet
    /// - Parameters:
    ///   - frames: The frames to process
    ///   - level: The encryption level
    /// - Returns: Processing result
    public func processFrames(
        _ frames: [Frame],
        level: EncryptionLevel
    ) throws -> FrameProcessingResult {
        var result = FrameProcessingResult()

        for frame in frames {
            switch frame {
            case .ack(let ackFrame):
                try processAckFrame(ackFrame, level: level)

            case .crypto(let cryptoFrame):
                try processCryptoFrame(cryptoFrame, level: level, result: &result)

            case .connectionClose(let closeFrame):
                processConnectionClose(closeFrame)
                result.connectionClosed = true

            case .handshakeDone:
                processHandshakeDone()
                result.handshakeComplete = true

            case .stream(let streamFrame):
                // Check if this is a new peer-initiated stream
                let isNewStream = !streamManager.hasStream(id: streamFrame.streamID)

                try streamManager.receive(frame: streamFrame)

                // Track new peer-initiated streams
                if isNewStream {
                    let isRemote = isRemoteStream(streamFrame.streamID)
                    if isRemote {
                        result.newStreams.append(streamFrame.streamID)
                    }
                }

                // Read available data from the stream
                if let data = streamManager.read(streamID: streamFrame.streamID) {
                    result.streamData.append((streamFrame.streamID, data))
                }

            case .resetStream(let resetFrame):
                try streamManager.handleResetStream(resetFrame)

            case .stopSending(let stopFrame):
                streamManager.handleStopSending(stopFrame)

            case .maxData(let maxData):
                streamManager.handleMaxData(MaxDataFrame(maxData: maxData))

            case .maxStreamData(let maxStreamDataFrame):
                streamManager.handleMaxStreamData(maxStreamDataFrame)

            case .maxStreams(let maxStreamsFrame):
                streamManager.handleMaxStreams(maxStreamsFrame)

            case .dataBlocked, .streamDataBlocked, .streamsBlocked:
                // Generate flow control frames as needed
                break

            case .padding, .ping:
                // No action needed
                break

            default:
                // Other frames handled as needed
                break
            }
        }

        return result
    }

    /// Processes an ACK frame
    ///
    /// RFC 9002 compliant ACK processing:
    /// 1. Process ACK to detect acked/lost packets and update RTT
    /// 2. Notify congestion controller of acknowledged packets
    /// 3. Handle packet loss with congestion control
    ///
    /// - Note: Uses internally managed `peerMaxAckDelay` for RTT/PTO calculations.
    private func processAckFrame(_ ackFrame: AckFrame, level: EncryptionLevel) throws {
        let now = ContinuousClock.Instant.now

        let result = pnSpaceManager.onAckReceived(
            ackFrame: ackFrame,
            level: level,
            receiveTime: now
        )

        // Congestion Control: process acknowledged packets
        if !result.ackedPackets.isEmpty {
            congestionController.onPacketsAcknowledged(
                packets: result.ackedPackets,
                now: now,
                rtt: pnSpaceManager.rttEstimator
            )
        }

        // Congestion Control: process lost packets
        if !result.lostPackets.isEmpty {
            // RFC 9002 Section 7.6.2 - Persistent Congestion
            //
            // Per the RFC, persistent congestion detection happens AFTER loss detection,
            // and causes an ADDITIONAL response beyond normal loss handling:
            // - Normal loss: cwnd reduced by half, enter recovery
            // - Persistent congestion: cwnd collapsed to minimum, ssthresh reset
            //
            // Implementation note:
            // We use if-else here because persistent congestion subsumes normal loss:
            // - Both would enter recovery, but persistent congestion also resets ssthresh
            // - Applying loss first (cwnd/2) then persistent congestion (cwnd=minimum)
            //   would give the same result as applying persistent congestion alone
            // - The key difference is ssthresh reset, which only persistent congestion does
            //
            // This optimization is valid because:
            // - minimum_window (2*MSS) < cwnd/2 for any cwnd > 4*MSS (always true after slow start)
            // - Persistent congestion resets to slow start (ssthresh=∞), which is the desired behavior
            if pnSpaceManager.checkPersistentCongestion(lostPackets: result.lostPackets) {
                congestionController.onPersistentCongestion()
            } else {
                congestionController.onPacketsLost(
                    packets: result.lostPackets,
                    now: now,
                    rtt: pnSpaceManager.rttEstimator
                )
            }
        }
    }

    /// Processes a CRYPTO frame
    private func processCryptoFrame(
        _ cryptoFrame: CryptoFrame,
        level: EncryptionLevel,
        result: inout FrameProcessingResult
    ) throws {
        // Buffer the crypto data
        try cryptoStreamManager.receive(cryptoFrame, at: level)

        // Try to read complete data
        if let data = cryptoStreamManager.read(at: level) {
            result.cryptoData.append((level, data))
        }
    }

    /// Processes CONNECTION_CLOSE frame
    private func processConnectionClose(_ closeFrame: ConnectionCloseFrame) {
        connectionState.withLock { state in
            state.status = .draining
        }
    }

    /// Processes HANDSHAKE_DONE frame
    private func processHandshakeDone() {
        handshakeComplete.withLock { $0 = true }
        connectionState.withLock { $0.status = .established }
        pnSpaceManager.handshakeConfirmed = true
    }

    /// Sets peer transport parameters (called after TLS handshake)
    ///
    /// This updates various components with the peer's advertised limits and settings,
    /// including the critical `max_ack_delay` used for RTT/PTO calculations.
    ///
    /// - Parameter params: Peer's transport parameters
    public func setPeerTransportParameters(_ params: TransportParameters) {
        peerTransportParams.withLock { $0 = params }

        // RFC 9002: Set peer's max_ack_delay for RTT/PTO calculations
        pnSpaceManager.peerMaxAckDelay = .milliseconds(Int64(params.maxAckDelay))

        // Update stream manager with peer's limits
        streamManager.handleMaxData(MaxDataFrame(maxData: params.initialMaxData))
        streamManager.handleMaxStreams(MaxStreamsFrame(
            maxStreams: params.initialMaxStreamsBidi,
            isBidirectional: true
        ))
        streamManager.handleMaxStreams(MaxStreamsFrame(
            maxStreams: params.initialMaxStreamsUni,
            isBidirectional: false
        ))

        // Update per-stream data limits
        // Note: Peer's bidi_local is our send limit for streams WE open
        //       Peer's bidi_remote is our send limit for streams PEER opens
        streamManager.updatePeerStreamDataLimits(
            bidiLocal: params.initialMaxStreamDataBidiLocal,
            bidiRemote: params.initialMaxStreamDataBidiRemote,
            uni: params.initialMaxStreamDataUni
        )
    }

    // MARK: - Key Management

    /// Installs keys for an encryption level
    /// - Parameter info: Information about the available keys
    public func installKeys(_ info: KeysAvailableInfo) throws {
        let role = connectionState.withLock { $0.role }

        // Determine which keys to use for read/write based on role
        let readKeys: KeyMaterial
        let writeKeys: KeyMaterial
        if role == .client {
            readKeys = try KeyMaterial.derive(from: info.serverSecret)
            writeKeys = try KeyMaterial.derive(from: info.clientSecret)
        } else {
            readKeys = try KeyMaterial.derive(from: info.clientSecret)
            writeKeys = try KeyMaterial.derive(from: info.serverSecret)
        }

        let opener = try AES128GCMOpener(keyMaterial: readKeys)
        let sealer = try AES128GCMSealer(keyMaterial: writeKeys)

        cryptoContexts.withLock { contexts in
            contexts[info.level] = CryptoContext(opener: opener, sealer: sealer)
        }

        // Update key schedule
        keySchedule.withLock { schedule in
            switch info.level {
            case .handshake:
                _ = try? schedule.setHandshakeSecrets(
                    clientSecret: info.clientSecret,
                    serverSecret: info.serverSecret
                )
            case .application:
                _ = try? schedule.setApplicationSecrets(
                    clientSecret: info.clientSecret,
                    serverSecret: info.serverSecret
                )
            default:
                break
            }
        }
    }

    /// Gets the crypto context for an encryption level
    /// - Parameter level: The encryption level
    /// - Returns: The crypto context, if available
    public func cryptoContext(for level: EncryptionLevel) -> CryptoContext? {
        cryptoContexts.withLock { $0[level] }
    }

    // MARK: - Packet Transmission

    /// Gets pending packets to send
    /// - Returns: Array of outbound packets
    public func getOutboundPackets() -> [OutboundPacket] {
        let now = ContinuousClock.Instant.now
        let ackDelayExponent = localTransportParams.ackDelayExponent
        var packets: [OutboundPacket] = []

        // Check if ACKs need to be sent
        for level in [EncryptionLevel.initial, .handshake, .application] {
            if let ackFrame = pnSpaceManager.generateAckFrame(
                for: level,
                now: now,
                ackDelayExponent: ackDelayExponent
            ) {
                queueFrame(.ack(ackFrame), level: level)
            }
        }

        // Generate stream frames (only at application level)
        if handshakeComplete.withLock({ $0 }) {
            let streamFrames = streamManager.generateStreamFrames(maxBytes: 1200)
            for streamFrame in streamFrames {
                queueFrame(.stream(streamFrame), level: .application)
            }

            // Generate flow control frames
            let flowFrames = streamManager.generateFlowControlFrames()
            for flowFrame in flowFrames {
                queueFrame(flowFrame, level: .application)
            }
        }

        // Get queued packets
        packets = outboundQueue.withLock { queue in
            let result = queue
            queue.removeAll()
            return result
        }

        return packets
    }

    /// Queues a frame to be sent
    public func queueFrame(_ frame: Frame, level: EncryptionLevel) {
        let packet = OutboundPacket(frames: [frame], level: level)
        outboundQueue.withLock { $0.append(packet) }
    }

    /// Queues CRYPTO frames to be sent
    public func queueCryptoData(_ data: Data, level: EncryptionLevel) {
        let frames = cryptoStreamManager.createFrames(for: data, at: level)
        for frame in frames {
            queueFrame(.crypto(frame), level: level)
        }
    }

    /// Records a sent packet for loss detection and congestion control
    /// - Parameter packet: The sent packet
    public func recordSentPacket(_ packet: SentPacket) {
        pnSpaceManager.onPacketSent(packet)

        // Notify congestion controller
        congestionController.onPacketSent(
            bytes: packet.sentBytes,
            now: packet.timeSent
        )
    }

    /// Gets the next packet number for an encryption level
    /// - Parameter level: The encryption level
    /// - Returns: The next packet number
    public func getNextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        connectionState.withLock { state in
            state.getNextPacketNumber(for: level)
        }
    }

    // MARK: - Timer Management

    /// Called when a timer expires
    /// - Returns: Actions to take (retransmit, probe, etc.)
    public func onTimerExpired() -> TimerAction {
        let now = ContinuousClock.Instant.now

        // Check for loss timeout
        if let (level, lossTime) = pnSpaceManager.earliestLossTime(), lossTime <= now {
            if let detector = pnSpaceManager.lossDetectors[level] {
                let rtt = pnSpaceManager.rttEstimator
                let lostPackets = detector.detectLostPackets(now: now, rttEstimator: rtt)
                if !lostPackets.isEmpty {
                    return .retransmit(lostPackets, level: level)
                }
            }
        }

        // Check for PTO (uses internally managed peerMaxAckDelay)
        let ptoDeadline = pnSpaceManager.nextPTODeadline(now: now)
        if ptoDeadline <= now {
            pnSpaceManager.onPTOExpired()
            return .probe
        }

        return .none
    }

    /// Gets the next timer deadline
    /// - Returns: When the next timer should fire
    public func nextTimerDeadline() -> ContinuousClock.Instant? {
        let now = ContinuousClock.Instant.now

        // Get earliest loss time
        let lossTime = pnSpaceManager.earliestLossTime()?.time

        // Get PTO time (uses internally managed peerMaxAckDelay)
        let ptoTime = pnSpaceManager.nextPTODeadline(now: now)

        // Get ACK time
        let ackTime = pnSpaceManager.earliestAckTime()?.time

        // Get pacing time (for smooth transmission)
        let pacingTime = congestionController.nextSendTime()

        // Return earliest
        return [lossTime, ptoTime, ackTime, pacingTime].compactMap { $0 }.min()
    }

    // MARK: - Congestion Control

    /// Checks if a packet can be sent (congestion window and pacing check)
    /// - Parameters:
    ///   - size: Size of the packet in bytes
    ///   - now: Current time
    /// - Returns: `true` if the packet can be sent
    public func canSendPacket(size: Int, now: ContinuousClock.Instant = .now) -> Bool {
        // 1. Check congestion window
        let bytesInFlight = pnSpaceManager.totalBytesInFlight
        guard congestionController.availableWindow(bytesInFlight: bytesInFlight) >= size else {
            return false
        }

        // 2. Check pacing
        if let nextTime = congestionController.nextSendTime() {
            guard now >= nextTime else {
                return false
            }
        }

        return true
    }

    /// Current congestion window in bytes
    public var congestionWindow: Int {
        congestionController.congestionWindow
    }

    /// Available window for sending (congestion window minus bytes in flight)
    public var availableWindow: Int {
        congestionController.availableWindow(bytesInFlight: pnSpaceManager.totalBytesInFlight)
    }

    /// Current congestion control state
    public var congestionState: CongestionState {
        congestionController.currentState
    }

    // MARK: - Stream Management

    /// Opens a new stream
    /// - Parameter bidirectional: Whether to create a bidirectional stream
    /// - Returns: The new stream ID
    /// - Throws: StreamManagerError if stream limit reached
    public func openStream(bidirectional: Bool) throws -> UInt64 {
        try streamManager.openStream(bidirectional: bidirectional)
    }

    /// Writes data to a stream
    /// - Parameters:
    ///   - streamID: Stream to write to
    ///   - data: Data to write
    /// - Throws: StreamManagerError on failures
    public func writeToStream(_ streamID: UInt64, data: Data) throws {
        try streamManager.write(streamID: streamID, data: data)
    }

    /// Finishes writing to a stream (sends FIN)
    /// - Parameter streamID: Stream to finish
    /// - Throws: StreamManagerError on failures
    public func finishStream(_ streamID: UInt64) throws {
        try streamManager.finish(streamID: streamID)
    }

    /// Reads data from a stream
    /// - Parameter streamID: Stream to read from
    /// - Returns: Available data, or nil if none
    public func readFromStream(_ streamID: UInt64) -> Data? {
        streamManager.read(streamID: streamID)
    }

    /// Closes a stream
    /// - Parameter streamID: Stream to close
    public func closeStream(_ streamID: UInt64) {
        streamManager.closeStream(id: streamID)
    }

    /// Checks if a stream has data to read
    /// - Parameter streamID: Stream to check
    /// - Returns: true if data available
    public func streamHasDataToRead(_ streamID: UInt64) -> Bool {
        streamManager.hasDataToRead(streamID: streamID)
    }

    /// Checks if a stream has data to send
    /// - Parameter streamID: Stream to check
    /// - Returns: true if data pending
    public func streamHasDataToSend(_ streamID: UInt64) -> Bool {
        streamManager.hasDataToSend(streamID: streamID)
    }

    /// Gets all active stream IDs
    public var activeStreamIDs: [UInt64] {
        streamManager.activeStreamIDs
    }

    /// Gets the number of active streams
    public var activeStreamCount: Int {
        streamManager.activeStreamCount
    }

    // MARK: - Connection Close

    /// Closes the connection
    /// - Parameter error: Optional error reason
    public func close(error: ConnectionCloseError? = nil) {
        connectionState.withLock { state in
            state.status = .draining
        }

        // Queue CONNECTION_CLOSE frame
        let closeFrame = ConnectionCloseFrame(
            errorCode: error?.code ?? 0,
            frameType: nil,
            reasonPhrase: error?.reason ?? ""
        )
        queueFrame(.connectionClose(closeFrame), level: .application)
    }

    // MARK: - Status

    /// Current connection status
    public var status: ConnectionStatus {
        connectionState.withLock { $0.status }
    }

    /// Whether the handshake is complete
    public var isHandshakeComplete: Bool {
        handshakeComplete.withLock { $0 }
    }

    /// Current RTT estimate
    public var rttEstimate: Duration {
        pnSpaceManager.rttEstimator.smoothedRTT
    }

    /// Checks if a stream ID is from the remote peer
    /// - Parameter streamID: The stream ID to check
    /// - Returns: True if the stream was initiated by the remote peer
    private func isRemoteStream(_ streamID: UInt64) -> Bool {
        let isClient = connectionState.withLock { $0.role == .client }
        let isClientInitiated = StreamID.isClientInitiated(streamID)
        // Remote stream: if we're client and stream is server-initiated, or vice versa
        return isClient != isClientInitiated
    }

    /// Connection role
    public var role: ConnectionRole {
        connectionState.withLock { $0.role }
    }

    /// Current source connection ID
    public var sourceConnectionID: ConnectionID {
        connectionState.withLock { $0.currentSourceCID }
    }

    /// Current destination connection ID
    public var destinationConnectionID: ConnectionID {
        connectionState.withLock { $0.currentDestinationCID }
    }

    /// QUIC version
    public var version: QUICVersion {
        connectionState.withLock { $0.version }
    }

    /// Discards an encryption level
    /// - Parameter level: The level to discard
    public func discardLevel(_ level: EncryptionLevel) {
        pnSpaceManager.discardLevel(level)
        cryptoStreamManager.discardLevel(level)
        cryptoContexts.withLock { $0.removeValue(forKey: level) }
        keySchedule.withLock { $0.discardKeys(for: level) }
    }
}

// MARK: - Supporting Types

/// Result of processing frames
public struct FrameProcessingResult: Sendable {
    /// Crypto data received at each level
    public var cryptoData: [(EncryptionLevel, Data)] = []

    /// Stream data received (stream ID, data)
    public var streamData: [(UInt64, Data)] = []

    /// New peer-initiated streams that were created
    public var newStreams: [UInt64] = []

    /// Whether the handshake completed
    public var handshakeComplete: Bool = false

    /// Whether the connection was closed
    public var connectionClosed: Bool = false
}

/// Packet to be sent
public struct OutboundPacket: Sendable {
    /// Frames in this packet
    public let frames: [Frame]

    /// Encryption level
    public let level: EncryptionLevel

    /// Creation time
    public let createdAt: ContinuousClock.Instant

    /// Creates an outbound packet
    public init(frames: [Frame], level: EncryptionLevel) {
        self.frames = frames
        self.level = level
        self.createdAt = .now
    }
}

/// Action to take on timer expiry
public enum TimerAction: Sendable {
    /// No action needed
    case none

    /// Retransmit lost packets at the specified level
    case retransmit([SentPacket], level: EncryptionLevel)

    /// Send probe packets
    case probe
}

/// Error for connection close
public struct ConnectionCloseError: Sendable {
    /// Error code
    public let code: UInt64

    /// Reason phrase
    public let reason: String

    /// Creates a connection close error
    public init(code: UInt64, reason: String = "") {
        self.code = code
        self.reason = reason
    }
}
