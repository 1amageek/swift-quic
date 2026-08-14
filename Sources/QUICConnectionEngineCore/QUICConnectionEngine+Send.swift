// QUICConnectionEngine+Send.swift
// The sans-IO outbound path: application API (open/write/read streams, queue
// handshake bytes, queue datagrams) plus `flush(nowNanos:)`, which assembles the
// queued frames into protected datagrams to hand back to the facade.

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICRecoveryCore
import QUICStreamCore

extension QUICConnectionEngine {
    // MARK: - Stream application API

    /// Opens a local stream (bidirectional or unidirectional) and returns its ID.
    public mutating func openStream(bidirectional: Bool) throws(QUICEngineError) -> UInt64 {
        guard status != .closed else { throw .connectionClosed }
        return try streams.openLocal(bidirectional: bidirectional)
    }

    /// Queues application bytes for a stream. The bytes are framed and sent by the
    /// next ``flush(nowNanos:)``.
    public mutating func writeStream(_ id: UInt64, data: [UInt8]) throws(QUICEngineError) {
        guard status != .closed else { throw .connectionClosed }
        guard var send = streams.sendStreams[id] else {
            throw .invalidState("write to unknown or receive-only stream \(id)")
        }
        do { try send.write(data) } catch { throw .stream(error) }
        streams.sendStreams[id] = send
    }

    /// Marks a stream's send side finished (queues FIN).
    public mutating func finishStream(_ id: UInt64) throws(QUICEngineError) {
        guard var send = streams.sendStreams[id] else {
            throw .invalidState("finish unknown or receive-only stream \(id)")
        }
        // `finishStream` is the application-facing close operation. Once FIN or
        // RESET has entered the send-side state machine, repeating close is a
        // successful no-op. This includes the RFC 9000 section 3.5 path where a
        // peer sends STOP_SENDING, we answer with RESET_STREAM, and its ACK moves
        // the stream to `resetRecvd` before the application releases the stream.
        switch send.sendState {
        case .dataSent, .dataRecvd, .resetSent, .resetRecvd:
            return
        case .ready, .send:
            break
        }
        do { try send.finish() } catch { throw .stream(error) }
        streams.sendStreams[id] = send
    }

    /// Abruptly resets a stream's send side.
    public mutating func resetStream(
        _ id: UInt64,
        errorCode: UInt64
    ) throws(QUICEngineError) {
        guard var send = streams.sendStreams[id] else {
            throw .invalidState("reset unknown or receive-only stream \(id)")
        }
        guard let frame = send.generateResetStream(errorCode: errorCode) else {
            throw .invalidState("stream \(id) reset already sent")
        }
        streams.sendStreams[id] = send
        var frames = pendingFrames[.application] ?? []
        frames.append(.resetStream(frame))
        pendingFrames[.application] = frames
    }

    /// Resets a stream after reliably delivering its prefix through `reliableSize`.
    public mutating func resetStreamAt(
        _ id: UInt64,
        errorCode: UInt64,
        reliableSize: UInt64
    ) throws(QUICEngineError) {
        guard peerEnableResetStreamAt else {
            throw .invalidState("peer did not advertise RESET_STREAM_AT")
        }
        guard var send = streams.sendStreams[id] else {
            throw .invalidState("partial reset of unknown or receive-only stream \(id)")
        }
        do {
            try send.requestResetStreamAt(
                errorCode: errorCode,
                reliableSize: reliableSize
            )
        } catch {
            throw .stream(error)
        }
        streams.sendStreams[id] = send
    }

    /// Requests that the peer stop its send side for a receive-capable stream.
    public mutating func stopSending(
        _ id: UInt64,
        errorCode: UInt64
    ) throws(QUICEngineError) {
        guard status != .closed else { throw .connectionClosed }
        guard streams.receiveStreams[id] != nil else {
            throw .invalidState("stop receiving unknown or send-only stream \(id)")
        }
        var frames = pendingFrames[.application] ?? []
        frames.append(
            .stopSending(
                StopSendingFrame(
                    streamID: id,
                    applicationErrorCode: errorCode
                )
            )
        )
        pendingFrames[.application] = frames
    }

    /// Drains contiguous received bytes from a stream's receive buffer.
    public mutating func readStream(_ id: UInt64) -> [UInt8]? {
        guard var recv = streams.receiveStreams[id] else { return nil }
        let data = recv.read()
        streams.receiveStreams[id] = recv
        return data
    }

    /// Whether the stream has contiguous data ready to read.
    public func streamHasData(_ id: UInt64) -> Bool {
        streams.receiveStreams[id]?.hasDataToRead ?? false
    }

    /// Whether the stream's receive side is finished: the peer sent a FIN (or a
    /// RESET) and every byte before it has been drained, so no further bytes will
    /// ever arrive. The application read surface uses this to signal clean
    /// end-of-stream (EOF) at the stream level — distinct from the whole connection
    /// closing. An unknown stream id is treated as not-yet-finished (a stream the
    /// peer may still open), never as a silent EOF.
    public func streamReadFinished(_ id: UInt64) -> Bool {
        guard let recv = streams.receiveStreams[id] else { return false }
        if recv.isReceiveClosed { return true }
        return recv.finReceived && !recv.hasDataToRead
    }

    // MARK: - Handshake / datagram application API

    /// Queues outbound CRYPTO bytes at an encryption level (the facade's TLS seam
    /// produces these). They are framed by the next flush.
    public mutating func queueHandshake(_ data: Span<UInt8>, level: EncryptionLevel) {
        var queue = cryptoSendQueue.take(level) ?? []
        queue.reserveCapacity(queue.count + data.count)
        data.bytes.withUnsafeBytes { source in
            queue.append(contentsOf: source)
        }
        cryptoSendQueue[level] = queue
    }

    /// Convenience boundary for callers that already own contiguous array
    /// storage. The array is borrowed; the engine performs only the ownership
    /// copy required to retain bytes until packetization.
    public mutating func queueHandshake(
        _ data: borrowing [UInt8],
        level: EncryptionLevel
    ) {
        queueHandshake(data.span, level: level)
    }

    /// Installs handshake/application keys derived by the facade's TLS seam. This
    /// is the boundary where the (async) handshake hands negotiated traffic
    /// secrets back to the (sync) engine.
    ///
    /// - Returns: Events produced by replaying packets that arrived before the
    ///   corresponding read keys. The caller must drain this output before
    ///   waiting for another datagram.
    public mutating func installKeys(
        level: EncryptionLevel,
        readSecret: [UInt8]?,
        writeSecret: [UInt8]?,
        suite: QUICProtectionSuite
    ) throws(QUICEngineError) -> QUICEngineOutput {
        try keys.install(level: level, readSecret: readSecret, writeSecret: writeSecret, suite: suite, isClient: isClient)
        guard readSecret != nil else { return QUICEngineOutput() }
        return try replayUndecryptablePackets(for: level)
    }

    /// Issues a caller-generated connection ID and reset token to the peer.
    ///
    /// Entropy and endpoint demultiplexing remain host responsibilities. The
    /// engine validates ordering, fixed CID length, uniqueness, and the peer's
    /// advertised active-ID limit before queueing the wire frame.
    public mutating func issueLocalConnectionID(
        sequenceNumber: UInt64,
        connectionID: ConnectionID,
        statelessResetToken: [UInt8],
        retirePriorTo: UInt64 = 0
    ) throws(QUICEngineError) {
        guard status != .closed else { throw .connectionClosed }
        guard connectionID.length == sourceConnectionID.length else {
            throw .invalidState("locally issued connection IDs must have one fixed length")
        }
        guard statelessResetToken.count == ProtocolLimits.statelessResetTokenLength else {
            throw .invalidState("a stateless reset token must contain exactly 16 bytes")
        }
        guard retirePriorTo <= sequenceNumber else {
            throw .invalidState("retirePriorTo must not exceed the issued sequence number")
        }
        let futureActiveCount = localConnectionIDs.records.reduce(into: 0) { count, record in
            if !record.isRetired && record.sequenceNumber >= retirePriorTo {
                count += 1
            }
        } + 1
        guard UInt64(futureActiveCount) <= peerActiveConnectionIDLimit else {
            throw .invalidState("issuing this connection ID exceeds the peer's active_connection_id_limit")
        }
        try localConnectionIDs.issue(
            sequenceNumber: sequenceNumber,
            connectionID: connectionID,
            statelessResetToken: statelessResetToken
        )
        let frame: NewConnectionIDFrame
        do {
            frame = try NewConnectionIDFrame(
                sequenceNumber: sequenceNumber,
                retirePriorTo: retirePriorTo,
                connectionID: connectionID,
                statelessResetToken: statelessResetToken
            )
        } catch {
            throw .invalidState("invalid local NEW_CONNECTION_ID values")
        }
        var pending = pendingFrames[.application] ?? []
        pending.append(.newConnectionID(frame))
        pendingFrames[.application] = pending
    }

    /// Applies the peer's validated transport parameters (RFC 9000 §18.2),
    /// wiring the peer's stream-count, connection-level, and per-stream send
    /// limits into the flow controller + stream set. The facade calls this once
    /// the TLS seam surfaces the peer's parameters (typically with
    /// ``markHandshakeComplete()``).
    public mutating func validateAndApplyPeerTransportParameters(
        _ tp: TransportParametersCore
    ) throws(QUICEngineError) {
        let expectedPeerInitialSource = destinationConnectionID
        guard let peerInitialSource = tp.initialSourceConnectionID else {
            throw .transportParameter("initial_source_connection_id is required")
        }
        guard peerInitialSource == expectedPeerInitialSource else {
            throw .transportParameter("initial_source_connection_id does not match the peer Initial SCID")
        }

        if isClient {
            guard let originalDestination = tp.originalDestinationConnectionID else {
                throw .transportParameter("original_destination_connection_id is required from a server")
            }
            guard originalDestination == config.originalDestinationConnectionID else {
                throw .transportParameter("original_destination_connection_id does not match the first client Initial")
            }
            if let retrySourceConnectionID {
                guard tp.retrySourceConnectionID == retrySourceConnectionID else {
                    throw .transportParameter("retry_source_connection_id does not match the processed Retry")
                }
            } else if tp.retrySourceConnectionID != nil {
                throw .transportParameter("retry_source_connection_id was sent without a processed Retry")
            }
        } else {
            guard tp.originalDestinationConnectionID == nil,
                  tp.retrySourceConnectionID == nil,
                  tp.statelessResetToken == nil,
                  tp.preferredAddress == nil else {
                throw .transportParameter("a client sent server-only transport parameters")
            }
        }

        applyPeerTransportParameters(tp)
    }

    package mutating func applyPeerTransportParameters(_ tp: TransportParametersCore) {
        streams.flowController.updateRemoteStreamLimit(tp.initialMaxStreamsBidi, bidirectional: true)
        streams.flowController.updateRemoteStreamLimit(tp.initialMaxStreamsUni, bidirectional: false)
        streams.flowController.updateConnectionSendLimit(tp.initialMaxData)
        streams.peerInitialMaxStreamDataBidiLocal = tp.initialMaxStreamDataBidiLocal
        streams.peerInitialMaxStreamDataBidiRemote = tp.initialMaxStreamDataBidiRemote
        streams.peerInitialMaxStreamDataUni = tp.initialMaxStreamDataUni
        peerMaxDatagramFrameSize = tp.maxDatagramFrameSize
        peerEnableResetStreamAt = tp.enableResetStreamAt
        peerAckDelayExponent = Self.boundedAckDelayExponent(tp.ackDelayExponent)
        peerMaxAckDelayNanos = Self.millisecondsToNanos(tp.maxAckDelay)
        peerActiveConnectionIDLimit = max(2, tp.activeConnectionIDLimit)
        if let token = tp.statelessResetToken,
           token.count == ProtocolLimits.statelessResetTokenLength {
            peerConnectionIDs.setInitialStatelessResetToken(token)
        }
    }

    /// Marks the handshake complete (called by the facade once the TLS seam
    /// reports completion). A server then owes HANDSHAKE_DONE and may discard
    /// Initial/Handshake keys (RFC 9001 §4.9).
    public mutating func markHandshakeComplete() {
        guard status == .handshaking else { return }
        status = .established
        if !isClient {
            handshakeDonePending = true
            markHandshakeConfirmed()
        }
        keys.discard(level: .initial)
        undecryptablePackets.discard(level: .initial)
        initialSpace.isDiscarded = true
    }

    /// Marks the handshake confirmed from TLS or HANDSHAKE_DONE and retires
    /// Handshake keys. This is intentionally distinct from handshake completion:
    /// a client completes before the server confirms receipt of its Finished.
    public mutating func markHandshakeConfirmed() {
        guard status != .closed else { return }
        handshakeConfirmed = true
        keys.discard(level: .handshake)
        undecryptablePackets.discard(level: .handshake)
        handshakeSpace.isDiscarded = true
    }

    /// Initiates a 1-RTT key update after handshake confirmation. The write
    /// generation advances immediately; receive keys are committed only after
    /// authenticating the peer's response under the corresponding phase.
    public mutating func performKeyUpdate() throws(QUICEngineError) -> UInt8 {
        guard handshakeConfirmed else {
            throw .invalidState("key update requires handshake confirmation")
        }
        return try keys.initiateKeyUpdate()
    }

    /// Queues an unreliable DATAGRAM payload (RFC 9221).
    public mutating func sendDatagram(_ payload: [UInt8]) throws(QUICEngineError) {
        guard status != .closed else { throw .connectionClosed }
        pendingDatagrams.append(payload)
    }

    /// Initiates a graceful close, producing a CONNECTION_CLOSE on the next flush.
    public mutating func close(errorCode: UInt64, reason: [UInt8], isApplicationError: Bool) {
        guard status != .closed else { return }
        pendingClose = .present(ConnectionCloseInfo(
            errorCode: errorCode, isApplicationError: isApplicationError, frameType: nil, reasonPhrase: reason))
        status = .closing
    }

    /// Marks the connection closed without emitting a CONNECTION_CLOSE frame.
    ///
    /// The async facade uses this when the datagram transport ends or a fatal
    /// receive error already makes the connection unusable.
    public mutating func markClosed() {
        status = .closed
        pendingClose = .absent
        undecryptablePackets.removeAll()
    }

    // MARK: - Flush

    /// Assembles all queued data into protected datagrams to send (sans-IO).
    public mutating func flush(nowNanos: UInt64) throws(QUICEngineError) -> [[UInt8]] {
        var output = QUICEngineOutput()
        try flushPending(nowNanos: nowNanos, into: &output)
        return output.datagramsToSend
    }

    /// Core assembly used by both `flush` and the tail of `receive`. Builds, in
    /// order: Initial → Handshake → 1-RTT packets carrying owed ACKs, queued
    /// CRYPTO/STREAM/control frames, then a CONNECTION_CLOSE if closing.
    mutating func flushPending(nowNanos: UInt64, into output: inout QUICEngineOutput) throws(QUICEngineError) {
        if status == .closed { return }

        // CONNECTION_CLOSE short-circuits everything else.
        if case .present(let close) = pendingClose {
            let level = currentSendLevel
            let frame = Frame.connectionClose(ConnectionCloseFrame(
                errorCode: close.errorCode,
                frameType: close.frameType,
                reasonPhrase: String(decoding: close.reasonPhrase, as: UTF8.self),
                isApplicationError: close.isApplicationError))
            guard let dgram = try buildDatagram(
                level: level,
                frames: [frame],
                nowNanos: nowNanos,
                padInitial: false
            ) else { return }
            output.datagramsToSend.append(dgram)
            status = .closed
            pendingClose = .absent
            return
        }

        // Build per-level packets in order. In this slice each datagram carries a
        // single level's frames (coalescing Initial+Handshake is a follow-up).
        for level in [EncryptionLevel.initial, .handshake, .application] {
            guard keys.hasWriteKeys(for: level) else { continue }
            if space(for: level).isDiscarded { continue }
            let frames = try collectFrames(for: level, nowNanos: nowNanos)
            guard !frames.isEmpty else { continue }
            let padInitial = (level == .initial)
            if let dgram = try buildDatagram(level: level, frames: frames, nowNanos: nowNanos, padInitial: padInitial) {
                output.datagramsToSend.append(dgram)
            }
        }
    }

    // MARK: - Frame collection

    private mutating func collectFrames(for level: EncryptionLevel, nowNanos: UInt64) throws(QUICEngineError) -> [Frame] {
        var frames = pendingFrames.take(level) ?? []

        // 0) PTO probe (RFC 9002 §6.2.4): an ack-eliciting PING.
        if pendingPing[level] == true {
            frames.append(.ping)
            pendingPing[level] = false
        }

        // 1) Owed ACK (RFC 9000 §13.2).
        let localAckDelayExponent = self.localAckDelayExponent
        if let ack = withSpace(level, { sp -> AckFrame? in
            guard sp.ackElicitingPending, sp.hasNewAckInformation else { return nil }
            let ackDelayNanos = sp.largestReceivedTimeNanos.map {
                nowNanos >= $0 ? nowNanos - $0 : 0
            } ?? 0
            let ackDelayWireUnits = Self.ackDelayWireUnits(
                delayNanos: ackDelayNanos,
                exponent: localAckDelayExponent
            )
            return sp.makeAckFrame(ackDelayWireUnits: ackDelayWireUnits)
        }) {
            frames.append(.ack(ack))
            withSpace(level) { $0.onAckSent() }
        }

        // 2) HANDSHAKE_DONE (server, application level only).
        if level == .application, handshakeDonePending {
            frames.append(.handshakeDone)
            handshakeDonePending = false
        }

        // 3) PATH_RESPONSE answers.
        if level == .application {
            for resp in pendingPathResponses { frames.append(.pathResponse(resp)) }
            pendingPathResponses.removeAll()
        }

        // 4) CRYPTO bytes queued for this level.
        if var pending = cryptoSendQueue[level], !pending.isEmpty {
            let offset = cryptoSendOffset[level] ?? 0
            frames.append(.crypto(CryptoFrame(offset: offset, data: pending)))
            cryptoSendOffset[level] = offset &+ UInt64(pending.count)
            pending.removeAll()
            cryptoSendQueue[level] = pending
        }

        // 5) STREAM + DATAGRAM frames only at the application level.
        if level == .application {
            collectStreamFrames(into: &frames)
            for payload in pendingDatagrams {
                frames.append(.datagram(DatagramFrame(data: payload, hasLength: true)))
            }
            pendingDatagrams.removeAll()
        }

        return frames
    }

    private mutating func collectStreamFrames(into frames: inout [Frame]) {
        // Honor connection-level send flow control across all streams.
        var connectionBudget = streams.flowController.connectionSendWindow
        for id in streams.sendStreams.keys.sorted() {
            guard connectionBudget > 0 else { break }
            guard var send = streams.sendStreams[id] else { continue }
            guard send.hasDataToSend else {
                // A stream with no pending data is NOT reset merely because it is
                // idle this tick (RFC 9000 §3.5/§19.4: RESET_STREAM is only sent
                // when the peer sent STOP_SENDING, or the application reset it).
                // Resetting an idle stream would tear down healthy streams on every
                // flush. Only honour an outstanding STOP_SENDING here.
                if let stopCode = send.stopSendingErrorCode,
                   let reset = send.generateResetStream(errorCode: stopCode) {
                    frames.append(.resetStream(reset))
                    streams.sendStreams[id] = send
                }
                continue
            }
            let cap = Int(min(connectionBudget, UInt64(Int.max)))
            let streamFrames = send.generateFrames(maxBytes: cap)
            for sf in streamFrames {
                frames.append(.stream(sf))
                let n = UInt64(sf.data.count)
                streams.flowController.recordBytesSent(n)
                connectionBudget = connectionBudget >= n ? connectionBudget - n : 0
            }
            if let partialReset = send.generateResetStreamAt() {
                frames.append(.resetStreamAt(partialReset))
            }
            streams.sendStreams[id] = send
        }
    }

    // MARK: - Datagram building

    /// Serializes one packet (one level's frames) into a protected datagram,
    /// records it in the loss detector / congestion controller, and charges the
    /// anti-amplification budget. Returns `nil` if anti-amplification blocks it.
    private mutating func buildDatagram(
        level: EncryptionLevel,
        frames: [Frame],
        nowNanos: UInt64,
        padInitial: Bool
    ) throws(QUICEngineError) -> [UInt8]? {
        var protector: SuiteProtector
        do {
            protector = try keys.writeProtector(for: level)
        } catch {
            queueUnsentFrames(frames, level: level)
            throw error
        }

        let confidentialityLimit = config.aeadUsageLimits.confidentialityLimit(for: protector.suite)
        if keys.writePacketCount(for: level) >= confidentialityLimit {
            guard level == .application, handshakeConfirmed else {
                status = .closed
                queueUnsentFrames(frames, level: level)
                throw .aeadLimitReached
            }
            do {
                _ = try keys.initiateKeyUpdate()
                protector = try keys.writeProtector(for: level)
            } catch {
                status = .closed
                queueUnsentFrames(frames, level: level)
                throw .aeadLimitReached
            }
        }

        let pn: UInt64
        switch level {
        case .initial:
            do { pn = try initialSpace.takeNextPacketNumber(at: level) } catch {
                queueUnsentFrames(frames, level: level)
                throw error
            }
        case .handshake:
            do { pn = try handshakeSpace.takeNextPacketNumber(at: level) } catch {
                queueUnsentFrames(frames, level: level)
                throw error
            }
        case .zeroRTT, .application:
            do { pn = try applicationSpace.takeNextPacketNumber(at: level) } catch {
                queueUnsentFrames(frames, level: level)
                throw error
            }
        }

        let ackEliciting = frames.contains { isAckElicitingOut($0) }
        let inFlight = ackEliciting || frames.contains { if case .padding = $0 { return true } else { return false } }

        // Count before serialization. This conservatively charges failed codec
        // attempts and guarantees a successful AEAD seal is never missed.
        keys.recordSealAttempt(for: level)
        let datagram: [UInt8]
        if level == .application {
            let headerProtectionProtector: SuiteProtector
            do {
                headerProtectionProtector = try keys.applicationWriteHeaderProtectionProtector()
            } catch {
                withSpace(level) { $0.nextPacketNumber = pn }
                queueUnsentFrames(frames, level: level)
                throw error
            }
            let header: ShortHeader
            do {
                header = try ShortHeader(
                    destinationConnectionID: destinationConnectionID,
                    packetNumber: pn,
                    packetNumberLength: 4,
                    spinBit: false,
                    keyPhase: keys.currentWriteKeyPhase == 1
                )
            } catch {
                queueUnsentFrames(frames, level: level)
                throw .invalidState("invalid local short-header construction")
            }
            do {
                datagram = try PacketParsingCore.serializeShortHeaderPacket(
                    frames: frames, header: header, packetNumber: pn, protector: protector,
                    headerProtectionProtector: headerProtectionProtector,
                    maxPacketSize: config.maxDatagramSize)
            } catch {
                queueUnsentFrames(frames, level: level)
                throw .packetParsing(error)
            }
        } else {
            let packetType: PacketType = (level == .initial) ? .initial : .handshake
            let header: LongHeader
            do {
                header = try LongHeader(
                    packetType: packetType,
                    version: version,
                    destinationConnectionID: destinationConnectionID,
                    sourceConnectionID: sourceConnectionID,
                    token: level == .initial && !initialToken.isEmpty ? initialToken : nil,
                    packetNumber: pn,
                    packetNumberLength: 4
                )
            } catch {
                queueUnsentFrames(frames, level: level)
                throw .invalidState("invalid local long-header construction")
            }
            do {
                datagram = try PacketParsingCore.serializeLongHeaderPacket(
                    frames: frames, header: header, packetNumber: pn, protector: protector,
                    maxPacketSize: config.maxDatagramSize, padToMinimum: padInitial)
            } catch {
                queueUnsentFrames(frames, level: level)
                throw .packetParsing(error)
            }
        }

        // Anti-amplification gate (RFC 9000 §8.1): a server may not send more than
        // 3x what it has received until the path is validated.
        guard antiAmplification.canSend(bytes: UInt64(datagram.count)) else {
            // The packet was already sealed. Its packet number must never be
            // reused with the same key, even though anti-amplification prevents
            // transmission; a gap in the packet-number space is valid.
            queueUnsentFrames(frames, level: level)
            return nil
        }
        antiAmplification.recordBytesSent(UInt64(datagram.count))

        // Record for loss detection + congestion control.
        let sent = SentPacketView(
            packetNumber: pn, timeSentNanos: nowNanos, sentBytes: datagram.count,
            inFlight: inFlight, ackEliciting: ackEliciting)
        withSpace(level) { $0.lossDetector.onPacketSent(sent) }
        if level == .application {
            keys.recordApplicationPacketSent(pn)
        }
        let retransmittable = frames.filter {
            $0.carriesRetransmittableInformation
        }
        if !retransmittable.isEmpty {
            var ledger = sentFrameLedger[level] ?? UInt64ValueMap<[Frame]>()
            ledger[pn] = retransmittable
            sentFrameLedger[level] = ledger
        }
        if inFlight {
            congestion.onPacketSent(bytes: datagram.count, nowNanos: nowNanos)
            pacer.consume(bytes: UInt64(datagram.count), nowNanos: nowNanos)
        }

        return datagram
    }

    mutating func acknowledgePacketFrames(
        _ packet: SentPacketView,
        level: EncryptionLevel
    ) {
        var ledger = sentFrameLedger[level] ?? UInt64ValueMap<[Frame]>()
        guard let frames = ledger.removeValue(forKey: packet.packetNumber) else { return }
        sentFrameLedger[level] = ledger
        for frame in frames {
            switch frame {
            case .stream(let streamFrame):
                guard var send = streams.sendStreams[streamFrame.streamID] else { continue }
                send.acknowledgeData(
                    upTo: streamFrame.offset + UInt64(streamFrame.data.count)
                )
                streams.sendStreams[streamFrame.streamID] = send
            case .resetStream(let resetFrame):
                guard var send = streams.sendStreams[resetFrame.streamID] else { continue }
                send.acknowledgeReset()
                streams.sendStreams[resetFrame.streamID] = send
            case .resetStreamAt(let resetFrame):
                guard var send = streams.sendStreams[resetFrame.streamID] else { continue }
                send.acknowledgeReset()
                streams.sendStreams[resetFrame.streamID] = send
            default:
                break
            }
        }
    }

    mutating func requeueLostPacketFrames(
        _ packets: [SentPacketView],
        level: EncryptionLevel
    ) {
        for packet in packets {
            var ledger = sentFrameLedger[level] ?? UInt64ValueMap<[Frame]>()
            if let frames = ledger.removeValue(forKey: packet.packetNumber) {
                var pending = pendingFrames[level] ?? []
                pending.append(contentsOf: frames)
                pendingFrames[level] = pending
            }
            sentFrameLedger[level] = ledger
        }
    }

    private mutating func queueUnsentFrames(
        _ frames: [Frame],
        level: EncryptionLevel
    ) {
        let recoverable = frames.filter { $0.carriesUnsentInformation }
        guard !recoverable.isEmpty else { return }
        var pending = pendingFrames[level] ?? []
        pending.insert(contentsOf: recoverable, at: 0)
        pendingFrames[level] = pending
    }

    private func isAckElicitingOut(_ frame: Frame) -> Bool {
        switch frame {
        case .ack, .padding, .connectionClose: return false
        default: return true
        }
    }
}

private extension Frame {
    var carriesRetransmittableInformation: Bool {
        switch self {
        case .padding, .ack, .connectionClose, .datagram, .pathResponse:
            return false
        default:
            return true
        }
    }

    var carriesUnsentInformation: Bool {
        if case .connectionClose = self { return false }
        return true
    }
}
