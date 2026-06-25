// QUICConnectionEngine+Send.swift
// The sans-IO outbound path: application API (open/write/read streams, queue
// handshake bytes, queue datagrams) plus `flush(nowNanos:)`, which assembles the
// queued frames into protected datagrams to hand back to the facade.

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICRecoveryCore
import QUICStreamCore
import P2PCoreCrypto

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
        do { try send.finish() } catch { throw .stream(error) }
        streams.sendStreams[id] = send
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
    public mutating func queueHandshake(_ data: [UInt8], level: EncryptionLevel) {
        cryptoSendQueue[level, default: []].append(contentsOf: data)
    }

    /// Installs handshake/application keys derived by the facade's TLS seam. This
    /// is the boundary where the (async) handshake hands negotiated traffic
    /// secrets back to the (sync) engine.
    public mutating func installKeys(
        level: EncryptionLevel,
        readSecret: [UInt8]?,
        writeSecret: [UInt8]?,
        suite: QUICProtectionSuite
    ) throws(QUICEngineError) {
        try keys.install(level: level, readSecret: readSecret, writeSecret: writeSecret, suite: suite, isClient: isClient)
    }

    /// Applies the peer's validated transport parameters (RFC 9000 §18.2),
    /// wiring the peer's stream-count, connection-level, and per-stream send
    /// limits into the flow controller + stream set. The facade calls this once
    /// the TLS seam surfaces the peer's parameters (typically with
    /// ``markHandshakeComplete()``).
    public mutating func applyPeerTransportParameters(_ tp: TransportParametersCore) {
        streams.flowController.updateRemoteStreamLimit(tp.initialMaxStreamsBidi, bidirectional: true)
        streams.flowController.updateRemoteStreamLimit(tp.initialMaxStreamsUni, bidirectional: false)
        streams.flowController.updateConnectionSendLimit(tp.initialMaxData)
        streams.peerInitialMaxStreamDataBidiLocal = tp.initialMaxStreamDataBidiLocal
        streams.peerInitialMaxStreamDataBidiRemote = tp.initialMaxStreamDataBidiRemote
        streams.peerInitialMaxStreamDataUni = tp.initialMaxStreamDataUni
        peerMaxDatagramFrameSize = tp.maxDatagramFrameSize
    }

    /// Marks the handshake complete (called by the facade once the TLS seam
    /// reports completion). A server then owes HANDSHAKE_DONE and may discard
    /// Initial/Handshake keys (RFC 9001 §4.9).
    public mutating func markHandshakeComplete() {
        guard status == .handshaking else { return }
        status = .established
        if !isClient {
            handshakeDonePending = true
            handshakeConfirmed = true
        }
        keys.discard(level: .initial)
        initialSpace.isDiscarded = true
    }

    /// Initiates a 1-RTT key update (RFC 9001 §6.1): derives the next generation
    /// of application read/write keys, installs them, flips the key phase, and
    /// returns the new phase bit. Subsequent short-header packets are sealed under
    /// the new phase. Throws if application keys are not yet installed.
    public mutating func performKeyUpdate() throws(QUICEngineError) -> UInt8 {
        try keys.initiateKeyUpdate()
    }

    /// Queues an unreliable DATAGRAM payload (RFC 9221).
    public mutating func sendDatagram(_ payload: [UInt8]) throws(QUICEngineError) {
        guard status != .closed else { throw .connectionClosed }
        pendingDatagrams.append(payload)
    }

    /// Initiates a graceful close, producing a CONNECTION_CLOSE on the next flush.
    public mutating func close(errorCode: UInt64, reason: [UInt8], isApplicationError: Bool) {
        guard status != .closed else { return }
        pendingClose = ConnectionCloseInfo(
            errorCode: errorCode, isApplicationError: isApplicationError, frameType: nil, reasonPhrase: reason)
        status = .closing
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
        if let close = pendingClose {
            let level = currentSendLevel
            let frame = Frame.connectionClose(ConnectionCloseFrame(
                errorCode: close.errorCode,
                frameType: close.frameType,
                reasonPhrase: String(decoding: close.reasonPhrase, as: UTF8.self),
                isApplicationError: close.isApplicationError))
            if let dgram = try buildDatagram(level: level, frames: [frame], nowNanos: nowNanos, padInitial: false) {
                output.datagramsToSend.append(dgram)
            }
            status = .closed
            pendingClose = nil
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
        var frames: [Frame] = []

        // 0) PTO probe (RFC 9002 §6.2.4): an ack-eliciting PING.
        if pendingPing[level] == true {
            frames.append(.ping)
            pendingPing[level] = false
        }

        // 1) Owed ACK (RFC 9000 §13.2).
        if let ack = withSpace(level, { sp -> AckFrame? in
            guard sp.ackElicitingPending, sp.hasNewAckInformation else { return nil }
            return sp.makeAckFrame(ackDelayScaled: 0)
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
        let protector: SuiteProtector<C>
        do { protector = try keys.writeProtector(for: level) } catch { throw error }

        let pn: UInt64
        switch level {
        case .initial:
            do { pn = try initialSpace.takeNextPacketNumber() } catch { throw error }
        case .handshake:
            do { pn = try handshakeSpace.takeNextPacketNumber() } catch { throw error }
        case .zeroRTT, .application:
            do { pn = try applicationSpace.takeNextPacketNumber() } catch { throw error }
        }

        let ackEliciting = frames.contains { isAckElicitingOut($0) }
        let inFlight = ackEliciting || frames.contains { if case .padding = $0 { return true } else { return false } }

        let datagram: [UInt8]
        if level == .application {
            let header = ShortHeader(
                destinationConnectionID: destinationConnectionID,
                packetNumber: pn,
                packetNumberLength: 4,
                spinBit: false,
                keyPhase: keys.currentKeyPhase == 1)
            do {
                datagram = try PacketParsingCore.serializeShortHeaderPacket(
                    frames: frames, header: header, packetNumber: pn, protector: protector,
                    maxPacketSize: config.maxDatagramSize)
            } catch { throw .packetParsing(error) }
        } else {
            let packetType: PacketType = (level == .initial) ? .initial : .handshake
            let header = LongHeader(
                packetType: packetType,
                version: version,
                destinationConnectionID: destinationConnectionID,
                sourceConnectionID: sourceConnectionID,
                token: nil,
                packetNumber: pn,
                packetNumberLength: 4)
            do {
                datagram = try PacketParsingCore.serializeLongHeaderPacket(
                    frames: frames, header: header, packetNumber: pn, protector: protector,
                    maxPacketSize: config.maxDatagramSize, padToMinimum: padInitial)
            } catch { throw .packetParsing(error) }
        }

        // Anti-amplification gate (RFC 9000 §8.1): a server may not send more than
        // 3x what it has received until the path is validated.
        guard antiAmplification.canSend(bytes: UInt64(datagram.count)) else {
            // Roll back the packet number we consumed so it is not skipped.
            withSpace(level) { $0.nextPacketNumber = pn }
            return nil
        }
        antiAmplification.recordBytesSent(UInt64(datagram.count))

        // Record for loss detection + congestion control.
        let sent = SentPacketView(
            packetNumber: pn, timeSentNanos: nowNanos, sentBytes: datagram.count,
            inFlight: inFlight, ackEliciting: ackEliciting)
        withSpace(level) { $0.lossDetector.onPacketSent(sent) }
        if inFlight {
            congestion.onPacketSent(bytes: datagram.count, nowNanos: nowNanos)
            pacer.consume(bytes: UInt64(datagram.count), nowNanos: nowNanos)
        }

        return datagram
    }

    private func isAckElicitingOut(_ frame: Frame) -> Bool {
        switch frame {
        case .ack, .padding, .connectionClose: return false
        default: return true
        }
    }
}
