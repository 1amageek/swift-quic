// QUICConnectionEngine+Receive.swift
// The sans-IO inbound path: decrypt an incoming UDP datagram (one or more
// coalesced packets), route each frame to the cores, update state, and collect
// the facade-facing events. No I/O, no clock except the injected `nowNanos`.

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICRecoveryCore
import QUICStreamCore
import P2PCoreCrypto

extension QUICConnectionEngine {
    /// Processes one inbound UDP datagram (sans-IO).
    ///
    /// - Parameters:
    ///   - datagram: The raw UDP payload (may contain coalesced QUIC packets).
    ///   - nowNanos: The monotonic receive time in nanoseconds.
    /// - Returns: The events + datagrams the facade must act on.
    /// - Throws: ``QUICEngineError`` on a fatal protocol error. A packet that
    ///   merely fails to decrypt with the current keys is dropped per RFC 9001
    ///   §5.5 (it does not throw — that would let an attacker kill the connection)
    ///   but a malformed frame or invariant violation IS a typed throw.
    public mutating func receive(
        datagram: [UInt8],
        nowNanos: UInt64
    ) throws(QUICEngineError) -> QUICEngineOutput {
        guard status != .closed else { throw .connectionClosed }

        var output = QUICEngineOutput()

        // Anti-amplification: count every received byte (RFC 9000 §8.1).
        antiAmplification.recordBytesReceived(UInt64(datagram.count))

        // Split coalesced packets (RFC 9000 §12.2).
        let ranges: [CoalescedPacketRange]
        do {
            ranges = try CoalescedDatagramCore.split(datagram: datagram, dcidLength: sourceConnectionID.bytes.count)
        } catch {
            // A malformed datagram boundary is dropped, not fatal.
            return output
        }

        var anyPacketProcessed = false
        for range in ranges {
            let packetBytes = Array(datagram[range.offset..<(range.offset + range.length)])
            // Decrypt + route a single packet. A decryption failure drops the
            // packet (returns nil) without aborting the connection.
            if let processed = try processPacket(packetBytes, isLongHeader: range.isLongHeader, nowNanos: nowNanos, into: &output) {
                anyPacketProcessed = anyPacketProcessed || processed
            }
        }

        if anyPacketProcessed {
            idleTimeout.recordActivity(nowNanos: nowNanos)
        }

        // After processing, assemble anything we now owe (ACKs, responses).
        try flushPending(nowNanos: nowNanos, into: &output)
        return output
    }

    // MARK: - Single packet

    private mutating func processPacket(
        _ bytes: [UInt8],
        isLongHeader: Bool,
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) -> Bool? {
        if isLongHeader {
            return try processLongHeaderPacket(bytes, nowNanos: nowNanos, into: &output)
        } else {
            return try processShortHeaderPacket(bytes, nowNanos: nowNanos, into: &output)
        }
    }

    private mutating func processLongHeaderPacket(
        _ bytes: [UInt8],
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) -> Bool? {
        guard let firstByte = bytes.first else { return nil }
        // Determine the level from the long-header type bits (RFC 9000 §17.2).
        let typeBits = (firstByte & 0x30) >> 4
        let level: EncryptionLevel
        switch typeBits {
        case 0x00: level = .initial
        case 0x01: level = .zeroRTT
        case 0x02: level = .handshake
        default:
            // Retry / Version Negotiation are not handled by this slice; drop.
            return nil
        }

        // No keys for this level yet → drop (RFC 9001 §5.7 buffering is the
        // facade's concern; the engine simply cannot decrypt yet).
        guard keys.hasReadKeys(for: level) else { return nil }

        let protector: SuiteProtector<C>
        do { protector = try keys.readProtector(for: level) } catch { return nil }

        let largestPN = space(for: level).largestReceived ?? 0
        let parsed: ParsedPacketCore
        do {
            parsed = try PacketParsingCore.parseLongHeaderPacket(bytes: bytes, protector: protector, largestPN: largestPN)
        } catch {
            // Decryption / parse failure on a single packet is non-fatal (drop).
            return nil
        }

        // Client adopts the server's SCID as the new DCID (RFC 9000 §7.2).
        if isClient, level == .initial, case .long(let lh) = parsed.header {
            destinationConnectionID = lh.sourceConnectionID
        }

        try route(parsed: parsed, level: level, nowNanos: nowNanos, into: &output)
        return true
    }

    private mutating func processShortHeaderPacket(
        _ bytes: [UInt8],
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) -> Bool? {
        let level = EncryptionLevel.application
        guard keys.hasReadKeys(for: level) else { return nil }

        let hpProtector: SuiteProtector<C>
        do { hpProtector = try keys.readProtector(for: level) } catch { return nil }

        let largestPN = applicationSpace.largestReceived ?? 0
        let dcidLength = sourceConnectionID.bytes.count

        // The opener selector returns the current-phase protector. A key update
        // initiated by the peer (phase flip) is committed by re-deriving on a
        // successful open; this slice accepts only the current phase and drops a
        // mismatched-phase packet rather than silently rolling keys.
        let currentPhase = keys.currentKeyPhase
        let parsed: ParsedPacketCore
        do {
            parsed = try PacketParsingCore.parseShortHeaderPacket(
                bytes: bytes,
                dcidLength: dcidLength,
                largestPN: largestPN,
                headerProtectionProtector: hpProtector,
                openerSelector: { phase throws(PacketParsingError) -> SuiteProtector<C>? in
                    // Accept only the current phase in this slice (RFC 9001 §6.3
                    // peer-initiated update live-wiring is deferred).
                    phase == currentPhase ? hpProtector : nil
                }
            )
        } catch {
            return nil
        }

        try route(parsed: parsed, level: level, nowNanos: nowNanos, into: &output)
        return true
    }

    // MARK: - Frame routing

    private mutating func route(
        parsed: ParsedPacketCore,
        level: EncryptionLevel,
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) {
        // A valid decrypted Handshake packet from the peer validates our address
        // for anti-amplification (RFC 9000 §8.1).
        if level == .handshake || level == .application {
            antiAmplification.validateAddress()
        }

        let ackEliciting = parsed.frames.contains { isAckEliciting($0) }
        withSpace(level) { $0.recordReceived(packetNumber: parsed.packetNumber, ackEliciting: ackEliciting, nowNanos: nowNanos) }

        for frame in parsed.frames {
            try handleFrame(frame, level: level, nowNanos: nowNanos, into: &output)
        }
    }

    private func isAckEliciting(_ frame: Frame) -> Bool {
        switch frame {
        case .ack, .padding, .connectionClose: return false
        default: return true
        }
    }

    private mutating func handleFrame(
        _ frame: Frame,
        level: EncryptionLevel,
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) {
        switch frame {
        case .padding, .ping:
            break

        case .ack(let ack):
            try handleAck(ack, level: level, nowNanos: nowNanos)

        case .crypto(let crypto):
            try handleCrypto(crypto, level: level, into: &output)

        case .stream(let stream):
            try handleStream(stream, into: &output)

        case .maxData(let maxData):
            streams.flowController.updateConnectionSendLimit(maxData)

        case .maxStreamData(let f):
            if var send = streams.sendStreams[f.streamID] {
                send.updateSendMaxData(f.maxStreamData)
                streams.sendStreams[f.streamID] = send
            }

        case .maxStreams(let f):
            // Peer raised our stream-count budget; FlowControllerCore tracks it.
            streams.flowController.updateRemoteStreamLimit(f.maxStreams, bidirectional: f.isBidirectional)

        case .resetStream(let f):
            _ = streams.ensureRemoteStream(f.streamID)
            if var recv = streams.receiveStreams[f.streamID] {
                do { try recv.handleResetStream(errorCode: f.applicationErrorCode, finalSize: f.finalSize) }
                catch { throw .stream(error) }
                streams.receiveStreams[f.streamID] = recv
                output.readableStreams.append(f.streamID)
            }

        case .stopSending(let f):
            if var send = streams.sendStreams[f.streamID] {
                send.handleStopSending(errorCode: f.applicationErrorCode)
                streams.sendStreams[f.streamID] = send
            }

        case .pathChallenge(let data):
            pendingPathResponses.append(data)

        case .pathResponse(let data):
            _ = pathValidation.handleResponse(data, nowNanos: nowNanos)

        case .connectionClose(let cc):
            let info = ConnectionCloseInfo(
                errorCode: cc.errorCode,
                isApplicationError: cc.isApplicationError,
                frameType: cc.frameType,
                reasonPhrase: Array(cc.reasonPhrase.utf8))
            output.peerClosed = true
            output.closeReason = info
            status = .closed

        case .handshakeDone:
            // Client confirms the handshake (RFC 9001 §4.1.2).
            if isClient {
                handshakeConfirmed = true
                keys.discard(level: .handshake)
                handshakeSpace.isDiscarded = true
            }

        case .datagram(let dg):
            output.datagrams.append(dg.data)

        case .newToken, .dataBlocked, .streamDataBlocked, .streamsBlocked,
             .newConnectionID, .retireConnectionID:
            // Accepted but not acted on in this slice (no state corruption).
            break
        }
    }

    // MARK: - Frame handlers

    private mutating func handleAck(
        _ ack: AckFrame,
        level: EncryptionLevel,
        nowNanos: UInt64
    ) throws(QUICEngineError) {
        let intervals = decodeAckIntervals(ack)
        let wasFirstAck = !space(for: level).hasReceivedAck
        let latestRTT = rtt.latestRTTNanos
        let smoothedRTT = rtt.smoothedRTTNanos
        let result = withSpace(level) { sp -> LossDetectorCore.AckResult in
            sp.hasReceivedAck = true
            return sp.lossDetector.onAckReceived(
                largestAcked: ack.largestAcknowledged,
                intervals: intervals,
                wasFirstAck: wasFirstAck,
                nowNanos: nowNanos,
                latestRTTNanos: latestRTT,
                smoothedRTTNanos: smoothedRTT)
        }

        // RTT update from the largest newly-acked ack-eliciting packet.
        if let sample = result.rttSampleNanos {
            let ackDelayNanos = Self.ackDelayNanos(
                wireUnits: ack.ackDelay,
                exponent: peerAckDelayExponent
            )
            rtt.update(
                latestRttNanos: sample,
                ackDelayNanos: ackDelayNanos,
                maxAckDelayNanos: peerMaxAckDelayNanos,
                handshakeConfirmed: handshakeConfirmed)
        }

        // Feed congestion control via the cored snapshot/packet types.
        let snapshot = RTTSnapshot(hasEstimate: rtt.latestRTTNanos > 0, smoothedRTTNanos: rtt.smoothedRTTNanos)
        if !result.acked.isEmpty {
            let ackedPackets = result.acked.map {
                CongestionPacket(sentBytes: $0.sentBytes, timeSentNanos: $0.timeSentNanos, inFlight: $0.inFlight)
            }
            congestion.onPacketsAcknowledged(packets: ackedPackets, nowNanos: nowNanos, rtt: snapshot)
            for pkt in result.acked { acknowledgePacketFrames(pkt) }
        }
        if !result.lost.isEmpty {
            let lostPackets = result.lost.map {
                CongestionPacket(sentBytes: $0.sentBytes, timeSentNanos: $0.timeSentNanos, inFlight: $0.inFlight)
            }
            congestion.onPacketsLost(packets: lostPackets, nowNanos: nowNanos, rtt: snapshot)
        }

        // A successful ACK resets the PTO backoff (RFC 9002 §6.2).
        if !result.acked.isEmpty {
            ptoCount = 0
        }
    }

    private mutating func acknowledgePacketFrames(_ packet: SentPacketView) {
        // Without a per-packet frame side-table in this slice, stream-data
        // acknowledgement is handled lazily by SendStreamCore as more data is
        // written/acked through generateFrames; nothing to do here for now.
        _ = packet
    }

    private mutating func handleCrypto(
        _ crypto: CryptoFrame,
        level: EncryptionLevel,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) {
        var buffer = cryptoReassembly[level] ?? StreamReassemblyBuffer(maxBufferSize: 1024 * 1024)
        do {
            try buffer.insert(offset: crypto.offset, data: crypto.data, fin: false)
        } catch {
            throw .cryptoClosureFailed("crypto reassembly: \(error)")
        }
        let ordered = buffer.readAllContiguous()
        cryptoReassembly[level] = buffer
        if let ordered, !ordered.isEmpty {
            output.handshakeData.append(HandshakeChunk(level: level, data: ordered))
        }
    }

    private mutating func handleStream(
        _ stream: StreamFrame,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) {
        let created = streams.ensureRemoteStream(stream.streamID)
        guard var recv = streams.receiveStreams[stream.streamID] else {
            // STREAM frame for a send-only or unknown local stream: ignore.
            return
        }

        // Connection-level flow control (RFC 9000 §4.1).
        let endOffset = stream.offset &+ UInt64(stream.data.count)
        let prevEnd = streams.flowController.streamBytesReceived(for: stream.streamID)
        if endOffset > prevEnd {
            let delta = endOffset - prevEnd
            guard streams.flowController.canReceive(bytes: delta) else {
                throw .flowControl("connection receive limit exceeded")
            }
            streams.flowController.recordBytesReceived(delta)
            _ = streams.flowController.recordStreamBytesReceived(stream.streamID, endOffset: endOffset)
        }

        do { try recv.receive(stream) } catch { throw .stream(error) }
        streams.receiveStreams[stream.streamID] = recv

        if created { output.newStreams.append(stream.streamID) }
        if recv.hasDataToRead { output.readableStreams.append(stream.streamID) }
    }

    // MARK: - ACK decoding

    private func decodeAckIntervals(_ ack: AckFrame) -> [AckInterval] {
        var intervals: [AckInterval] = []
        var current = ack.largestAcknowledged
        for (i, range) in ack.ackRanges.enumerated() {
            if i == 0 {
                let start = current >= range.rangeLength ? current - range.rangeLength : 0
                intervals.append(AckInterval(start: start, end: current))
                current = start
            } else {
                // gap accounts for (gap + 1) unacked packets, then a +1 boundary.
                let gapTotal = range.gap &+ 2
                if current >= gapTotal {
                    current = current - gapTotal
                } else {
                    break
                }
                let start = current >= range.rangeLength ? current - range.rangeLength : 0
                intervals.append(AckInterval(start: start, end: current))
                current = start
            }
        }
        return intervals
    }
}
