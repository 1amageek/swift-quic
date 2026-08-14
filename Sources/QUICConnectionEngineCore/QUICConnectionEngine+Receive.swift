// QUICConnectionEngine+Receive.swift
// The sans-IO inbound path: decrypt an incoming UDP datagram (one or more
// coalesced packets), route each frame to the cores, update state, and collect
// the facade-facing events. No I/O, no clock except the injected `nowNanos`.

import NetworkingCore
import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICRecoveryCore
import QUICStreamCore

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
        datagram: Span<UInt8>,
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
            let packetBytes = datagram.extracting(range.offset..<(range.offset + range.length))
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

    public mutating func receive(
        datagram: borrowing [UInt8],
        nowNanos: UInt64
    ) throws(QUICEngineError) -> QUICEngineOutput {
        try receive(datagram: datagram.span, nowNanos: nowNanos)
    }

    // MARK: - Single packet

    mutating func processPacket(
        _ bytes: Span<UInt8>,
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
        _ bytes: Span<UInt8>,
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) -> Bool? {
        guard !bytes.isEmpty else { return nil }
        let protectedHeader: ProtectedLongHeader
        let protectedHeaderLength: Int
        do {
            (protectedHeader, protectedHeaderLength) = try ProtectedLongHeader.parse(from: bytes)
        } catch {
            return nil
        }

        switch protectedHeader.packetType {
        case .versionNegotiation:
            return try processVersionNegotiation(
                protectedHeader,
                headerLength: protectedHeaderLength,
                bytes: bytes
            )
        case .retry:
            return try processRetry(protectedHeader, bytes: bytes, nowNanos: nowNanos)
        default:
            break
        }

        guard protectedHeader.version == version else { return nil }
        let level: EncryptionLevel
        switch protectedHeader.packetType {
        case .initial: level = .initial
        case .zeroRTT: level = .zeroRTT
        case .handshake: level = .handshake
        case .retry, .versionNegotiation: return nil
        }

        guard !space(for: level).isDiscarded else { return nil }

        // RFC 9001 section 5.7 requires packets that arrive before their keys to
        // be retained for later processing. The scoped input borrow is copied
        // once into a count- and byte-bounded connection-owned buffer.
        guard keys.hasReadKeys(for: level) else {
            undecryptablePackets.append(
                bytes,
                level: level,
                isLongHeader: true,
                receivedAtNanos: nowNanos
            )
            return nil
        }

        let protector: SuiteProtector
        do { protector = try keys.readProtector(for: level) } catch { return nil }

        let largestPN = space(for: level).largestReceived ?? 0
        let parsed: ParsedPacketCore
        do {
            parsed = try PacketParsingCore.parseLongHeaderPacket(bytes: bytes, protector: protector, largestPN: largestPN)
        } catch let error {
            // Only frame decoding happens after AEAD authentication. An
            // authenticated malformed frame is connection-fatal; unauthenticated
            // structural/protection failures remain packet drops.
            if case .frame = error {
                throw .packetParsing(error)
            }
            try recordAuthenticationFailureIfNeeded(error, suite: protector.suite)
            return nil
        }

        if case .long(let header) = parsed.header {
            let acceptsOriginalDestination = !isClient
                && level == .initial
                && header.destinationConnectionID == config.originalDestinationConnectionID
            guard localConnectionIDs.containsActive(header.destinationConnectionID)
                    || acceptsOriginalDestination else {
                return nil
            }
        }

        // Client adopts only the first authenticated server Initial SCID. A
        // second change is not permitted during connection establishment.
        if isClient, level == .initial, case .long(let lh) = parsed.header {
            if let peerInitialSourceConnectionID {
                guard peerInitialSourceConnectionID == lh.sourceConnectionID else {
                    return nil
                }
            } else {
                peerInitialSourceConnectionID = lh.sourceConnectionID
                destinationConnectionID = lh.sourceConnectionID
                peerConnectionIDs.replaceInitialConnectionID(lh.sourceConnectionID)
            }
        }

        try route(parsed: parsed, level: level, nowNanos: nowNanos, into: &output)
        processedAuthenticatedPeerPacket = true
        return true
    }

    private mutating func processShortHeaderPacket(
        _ bytes: Span<UInt8>,
        nowNanos: UInt64,
        into output: inout QUICEngineOutput
    ) throws(QUICEngineError) -> Bool? {
        let level = EncryptionLevel.application
        guard keys.hasReadKeys(for: level) else {
            undecryptablePackets.append(
                bytes,
                level: level,
                isLongHeader: false,
                receivedAtNanos: nowNanos
            )
            return nil
        }

        let hpProtector: SuiteProtector
        do { hpProtector = try keys.applicationReadHeaderProtectionProtector() }
        catch { return nil }

        let largestPN = applicationSpace.largestReceived ?? 0
        let dcidLength = sourceConnectionID.bytes.count

        let parsed: ParsedPacketCore
        do {
            parsed = try PacketParsingCore.parseShortHeaderPacket(
                bytes: bytes,
                dcidLength: dcidLength,
                largestPN: largestPN,
                headerProtectionProtector: hpProtector,
                openerSelector: { phase, packetNumber throws(PacketParsingError) -> SuiteProtector? in
                    keys.applicationReadProtector(
                        keyPhase: phase,
                        packetNumber: packetNumber
                    )
                }
            )
        } catch let error {
            if case .frame = error {
                throw .packetParsing(error)
            }
            let suite = keys.appSuite ?? hpProtector.suite
            try recordAuthenticationFailureIfNeeded(error, suite: suite)
            if peerConnectionIDs.matchesActiveResetToken(packet: bytes) {
                status = .closed
                output.peerClosed = true
                return true
            }
            return nil
        }


        guard case .short(let header) = parsed.header,
              localConnectionIDs.containsActive(header.destinationConnectionID) else {
            return nil
        }

        if let keyPhase = parsed.keyPhase,
           keys.packetUsesNextReadGeneration(
               keyPhase: keyPhase,
               packetNumber: parsed.packetNumber
           ) {
            let committedPhase = try keys.commitNextReadGeneration(
                packetNumber: parsed.packetNumber
            )
            previousReadKeysDiscardDeadlineNanos = previousReadKeyDeadline(
                nowNanos: nowNanos
            )
            try keys.alignWriteGeneration(to: committedPhase)
        }

        try route(parsed: parsed, level: level, nowNanos: nowNanos, into: &output)
        processedAuthenticatedPeerPacket = true
        return true
    }

    private mutating func processVersionNegotiation(
        _ header: ProtectedLongHeader,
        headerLength: Int,
        bytes: Span<UInt8>
    ) throws(QUICEngineError) -> Bool? {
        guard isClient,
              !processedAuthenticatedPeerPacket,
              !processedRetry,
              header.destinationConnectionID == sourceConnectionID,
              header.sourceConnectionID == config.originalDestinationConnectionID else {
            return nil
        }
        let versionBytes = bytes.count - headerLength
        guard versionBytes > 0, versionBytes % 4 == 0 else { return nil }

        var reader = QUICWireReader(bytes.extracting(headerLength..<bytes.count))
        var advertised: [UInt32] = []
        advertised.reserveCapacity(versionBytes / 4)
        while reader.remaining > 0 {
            do {
                advertised.append(try reader.readUInt32())
            } catch {
                return nil
            }
        }
        // A VN packet listing the attempted version is downgrade noise and MUST
        // be discarded rather than causing the attempt to fail.
        guard !advertised.contains(version.rawValue) else { return nil }
        throw .versionNegotiationRequired(supportedVersions: advertised)
    }

    private mutating func processRetry(
        _ header: ProtectedLongHeader,
        bytes: Span<UInt8>,
        nowNanos: UInt64
    ) throws(QUICEngineError) -> Bool? {
        guard isClient,
              !processedRetry,
              !processedAuthenticatedPeerPacket,
              header.version == version,
              header.destinationConnectionID == sourceConnectionID,
              header.sourceConnectionID != config.originalDestinationConnectionID,
              let token = header.token,
              !token.isEmpty,
              let tag = header.retryIntegrityTag,
              bytes.count >= RetryIntegrityCore.tagLength else {
            return nil
        }

        let withoutTag = bytes.extracting(0..<(bytes.count - RetryIntegrityCore.tagLength))
        let valid: Bool
        do {
            valid = try RetryIntegrityCore.verify(
                tag: tag.span,
                originalDestinationConnectionID: config.originalDestinationConnectionID,
                retryPacketWithoutTag: withoutTag,
                version: version
            )
        } catch {
            return nil
        }
        guard valid else { return nil }

        // Replay the exact Initial CRYPTO information under a fresh packet-number
        // space and keys derived from the Retry SCID (RFC 9000 section 17.2.5.3).
        var replay = pendingFrames[.initial] ?? []
        if let ledger = sentFrameLedger[.initial] {
            for frames in ledger.values {
                replay.append(contentsOf: frames)
            }
        }
        pendingFrames[.initial] = replay
        sentFrameLedger[.initial] = UInt64ValueMap<[Frame]>()
        initialSpace = PacketNumberSpace()
        ptoCount = 0
        congestion = CubicCore(maxDatagramSize: config.maxDatagramSize)
        pacer = PacerCore(
            rate: UInt64.max,
            maxBurst: UInt64(config.maxDatagramSize) * 10,
            nowNanos: nowNanos
        )
        keys.discard(level: .zeroRTT)
        guard let salt = version.initialSaltBytes else {
            throw .transportParameter("unsupported QUIC version (no initial salt)")
        }
        try keys.installInitial(
            connectionID: header.sourceConnectionID.bytes,
            salt: salt,
            isClient: true
        )
        destinationConnectionID = header.sourceConnectionID
        retrySourceConnectionID = header.sourceConnectionID
        initialToken = token
        processedRetry = true
        return true
    }

    /// Reprocesses packets for one encryption level immediately after TLS
    /// installs matching read keys. Output intentionally excludes a final flush;
    /// the facade flushes once after it applies the complete ordered TLS batch.
    mutating func replayUndecryptablePackets(
        for level: EncryptionLevel
    ) throws(QUICEngineError) -> QUICEngineOutput {
        var output = QUICEngineOutput()
        let buffered = undecryptablePackets.take(level: level)
        var latestProcessedAt: UInt64?

        for packet in buffered {
            if let processed = try processPacket(
                packet.bytes.span,
                isLongHeader: packet.isLongHeader,
                nowNanos: packet.receivedAtNanos,
                into: &output
            ), processed {
                latestProcessedAt = max(
                    latestProcessedAt ?? packet.receivedAtNanos,
                    packet.receivedAtNanos
                )
            }
        }
        if let latestProcessedAt {
            idleTimeout.recordActivity(nowNanos: latestProcessedAt)
        }
        return output
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
            try handleFrame(
                frame,
                level: level,
                receivedDestinationConnectionID: parsed.header.destinationConnectionID,
                nowNanos: nowNanos,
                into: &output
            )
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
        receivedDestinationConnectionID: ConnectionID,
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

        case .resetStreamAt(let f):
            guard config.localTransportParameters.enableResetStreamAt else {
                throw .protocolViolation("RESET_STREAM_AT received without negotiation")
            }
            _ = streams.ensureRemoteStream(f.streamID)
            if var recv = streams.receiveStreams[f.streamID] {
                do {
                    try recv.handleResetStreamAt(
                        errorCode: f.applicationErrorCode,
                        finalSize: f.finalSize,
                        reliableSize: f.reliableSize
                    )
                } catch {
                    throw .stream(error)
                }
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
                markHandshakeConfirmed()
            }

        case .datagram(let dg):
            output.datagrams.append(dg.data)

        case .dataBlocked, .streamDataBlocked, .streamsBlocked:
            // Advisory flow-control telemetry. No state transition is required.
            break

        case .newToken:
            // NEW_TOKEN is optional for a client that does not persist address
            // validation tokens. Ignoring it is explicitly permitted by RFC 9000.
            break

        case .newConnectionID(let frame):
            var candidate = peerConnectionIDs
            let retired = try candidate.receive(
                frame,
                activeLimit: max(2, config.localTransportParameters.activeConnectionIDLimit)
            )
            peerConnectionIDs = candidate
            if !retired.isEmpty {
                var pending = pendingFrames[.application] ?? []
                for sequenceNumber in retired {
                    pending.append(.retireConnectionID(sequenceNumber))
                }
                pendingFrames[.application] = pending
            }
            if !peerConnectionIDs.containsActive(destinationConnectionID),
               let replacement = peerConnectionIDs.firstActive() {
                destinationConnectionID = replacement.connectionID
            }

        case .retireConnectionID(let sequenceNumber):
            guard let record = localConnectionIDs.record(sequenceNumber: sequenceNumber) else {
                throw .protocolViolation("RETIRE_CONNECTION_ID exceeds the largest issued sequence number")
            }
            guard record.connectionID != receivedDestinationConnectionID else {
                throw .protocolViolation("RETIRE_CONNECTION_ID refers to the packet destination connection ID")
            }
            _ = localConnectionIDs.retire(sequenceNumber: sequenceNumber)
            if sourceConnectionID == record.connectionID,
               let replacement = localConnectionIDs.firstActive() {
                sourceConnectionID = replacement.connectionID
            }
        }
    }

    private mutating func recordAuthenticationFailureIfNeeded(
        _ error: PacketParsingError,
        suite: QUICProtectionSuite
    ) throws(QUICEngineError) {
        guard case .protection(.aead(.authenticationFailed)) = error else { return }
        let failures = keys.recordFailedAuthentication()
        if failures > config.aeadUsageLimits.integrityLimit(for: suite) {
            status = .closed
            throw .aeadLimitReached
        }
    }

    private func previousReadKeyDeadline(nowNanos: UInt64) -> UInt64 {
        let pto = rtt.probeTimeoutNanos(maxAckDelayNanos: peerMaxAckDelayNanos)
        let (retention, multiplyOverflow) = pto.multipliedReportingOverflow(by: 3)
        if multiplyOverflow { return UInt64.max }
        let (deadline, addOverflow) = nowNanos.addingReportingOverflow(retention)
        return addOverflow ? UInt64.max : deadline
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
            for packet in result.acked {
                acknowledgePacketFrames(packet, level: level)
                if level == .application {
                    keys.recordApplicationPacketAcknowledged(packet.packetNumber)
                }
            }
        }
        if !result.lost.isEmpty {
            let lostPackets = result.lost.map {
                CongestionPacket(sentBytes: $0.sentBytes, timeSentNanos: $0.timeSentNanos, inFlight: $0.inFlight)
            }
            congestion.onPacketsLost(packets: lostPackets, nowNanos: nowNanos, rtt: snapshot)
            requeueLostPacketFrames(result.lost, level: level)
        }

        // A successful ACK resets the PTO backoff (RFC 9002 §6.2).
        if !result.acked.isEmpty {
            ptoCount = 0
        }
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
            var framer = cryptoMessageFraming[level] ?? QUICCryptoMessageFramer()
            let messages = try framer.append(ordered)
            cryptoMessageFraming[level] = framer
            for message in messages {
                output.handshakeData.append(
                    HandshakeChunk(level: level, data: message)
                )
            }
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
        guard let dataLength = UInt64(exactly: stream.data.count) else {
            throw .flowControl("STREAM payload length cannot be represented")
        }
        let (endOffset, offsetOverflow) = stream.offset.addingReportingOverflow(dataLength)
        guard !offsetOverflow else {
            throw .flowControl("STREAM end offset overflow")
        }
        guard endOffset <= ReceiveStreamCore.maxFinalOffset else {
            throw .flowControl("STREAM end offset exceeds the QUIC 62-bit limit")
        }
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
        // A FIN-only frame changes the application-visible read result from
        // "would block" to EOF even though it carries no payload. Surface that
        // transition so event-driven readers do not wait until an unrelated
        // packet or the connection idle timeout.
        if recv.hasDataToRead || recv.finReceived || recv.isReceiveClosed {
            output.readableStreams.append(stream.streamID)
        }
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
