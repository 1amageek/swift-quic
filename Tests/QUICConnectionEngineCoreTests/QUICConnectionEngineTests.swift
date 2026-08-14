// QUICConnectionEngineTests.swift
// Host tests for the cored QUICConnectionEngine. They drive the value-type,
// caller-locked, sans-IO, clock-free engine directly — time is injected as an
// explicit `nowNanos`, with NO real sleeps (mirroring the DTLS engine timer
// tests). A loopback pair (client + server) exercises the receive/send path over
// Initial keys, which both peers derive identically from the original DCID.

import Testing
import NetworkingCore
import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
@testable import QUICConnectionEngineCore

private typealias Engine = QUICConnectionEngine

@Suite("QUICConnectionEngine — cored, clock-free orchestrator")
struct QUICConnectionEngineTests {

    // MARK: - Helpers

    private func makeConfig(role: QUICEngineRole, dcid: ConnectionID, scid: ConnectionID, idleNanos: UInt64 = 30_000_000_000) -> QUICConnectionEngineConfiguration {
        var tp = TransportParametersCore()
        tp.initialMaxData = 1_000_000
        tp.initialMaxStreamDataBidiLocal = 256 * 1024
        tp.initialMaxStreamDataBidiRemote = 256 * 1024
        tp.initialMaxStreamDataUni = 256 * 1024
        tp.initialMaxStreamsBidi = 100
        tp.initialMaxStreamsUni = 100
        tp.enableResetStreamAt = true
        return QUICConnectionEngineConfiguration(
            role: role,
            version: .v1,
            localConnectionID: scid,
            initialPeerConnectionID: dcid,
            originalDestinationConnectionID: dcid,
            localTransportParameters: tp,
            maxDatagramSize: 1200,
            idleTimeoutNanos: idleNanos,
            maxAckDelayNanos: 25_000_000,
            pathValidationTimeoutNanos: 3_000_000_000
        )
    }

    /// Builds a client + server engine pair that share the original DCID, so both
    /// install identical Initial keys (RFC 9001 §5.2) — enough to round-trip
    /// 1-RTT-shaped Initial packets in these unit tests without a TLS handshake.
    private func makePair(
        idleNanos: UInt64 = 30_000_000_000,
        aeadUsageLimits: QUICAEADUsageLimits = QUICAEADUsageLimits()
    ) throws -> (client: Engine, server: Engine, dcid: ConnectionID, clientSCID: ConnectionID, serverSCID: ConnectionID) {
        let dcid = try #require(ConnectionID.random(length: 8))
        let clientSCID = try #require(ConnectionID.random(length: 8))
        let serverSCID = try #require(ConnectionID.random(length: 8))
        var clientConfiguration = makeConfig(
            role: .client,
            dcid: dcid,
            scid: clientSCID,
            idleNanos: idleNanos
        )
        // This helper constructs an already-established pair. At that point the
        // client has authenticated the server Initial SCID and uses it for both
        // packet destinations and peer connection-ID state.
        clientConfiguration.initialPeerConnectionID = serverSCID
        clientConfiguration.aeadUsageLimits = aeadUsageLimits
        var client = try Engine(configuration: clientConfiguration, nowNanos: 0)
        // The server's "peer CID" is the client's SCID; both derive Initial keys
        // from the SAME original DCID.
        var serverCfg = makeConfig(role: .server, dcid: clientSCID, scid: serverSCID, idleNanos: idleNanos)
        serverCfg.originalDestinationConnectionID = dcid
        serverCfg.aeadUsageLimits = aeadUsageLimits
        var server = try Engine(configuration: serverCfg, nowNanos: 0)
        // Simulate the handshake's transport-parameter exchange so both peers know
        // each other's stream-count + flow-control limits.
        var peerTP = TransportParametersCore()
        peerTP.initialMaxData = 1_000_000
        peerTP.initialMaxStreamDataBidiLocal = 256 * 1024
        peerTP.initialMaxStreamDataBidiRemote = 256 * 1024
        peerTP.initialMaxStreamDataUni = 256 * 1024
        peerTP.initialMaxStreamsBidi = 100
        peerTP.initialMaxStreamsUni = 100
        peerTP.enableResetStreamAt = true
        client.applyPeerTransportParameters(peerTP)
        server.applyPeerTransportParameters(peerTP)

        // Simulate the handshake's key install: both peers install matching
        // application (1-RTT) keys so STREAM data flows. The client's WRITE secret
        // is the server's READ secret and vice versa (RFC 9001 §5.1).
        let clientToServer = [UInt8](repeating: 0xC0, count: 32)
        let serverToClient = [UInt8](repeating: 0x05, count: 32)
        try client.installKeys(level: .application, readSecret: serverToClient, writeSecret: clientToServer, suite: .aes128GCM)
        try server.installKeys(level: .application, readSecret: clientToServer, writeSecret: serverToClient, suite: .aes128GCM)
        // Discard Initial keys + validate the path so anti-amplification doesn't
        // block 1-RTT sends (post-handshake state).
        client.markHandshakeComplete()
        server.markHandshakeComplete()
        client.markHandshakeConfirmed()
        return (client, server, dcid, clientSCID, serverSCID)
    }

    private func applicationProtector(
        secretByte: UInt8 = 0xC0
    ) throws -> SuiteProtector {
        try QUICKeyDerivation.protector(
            secret: [UInt8](repeating: secretByte, count: 32),
            suite: .aes128GCM
        )
    }

    private func retryPacket(
        originalDestinationConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID,
        sourceConnectionID: ConnectionID,
        token: [UInt8],
        version: QUICVersion = .v1
    ) throws -> [UInt8] {
        let header = try LongHeader(
            packetType: .retry,
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: token
        )
        var writer = QUICWireWriter(reservingCapacity: 23 + token.count)
        writer.writeByte(header.firstByte)
        writer.writeUInt32(version.rawValue)
        destinationConnectionID.encode(to: &writer)
        sourceConnectionID.encode(to: &writer)
        writer.writeBytes(token)
        var packet = writer.finishArray()
        let tag = try RetryIntegrityCore.compute(
            originalDestinationConnectionID: originalDestinationConnectionID,
            retryPacketWithoutTag: packet.span,
            version: version
        )
        packet.append(contentsOf: tag)
        return packet
    }

    private func versionNegotiationPacket(
        destinationConnectionID: ConnectionID,
        sourceConnectionID: ConnectionID,
        versions: [QUICVersion]
    ) -> [UInt8] {
        var writer = QUICWireWriter()
        writer.writeByte(0xc0)
        writer.writeUInt32(QUICVersion.negotiation.rawValue)
        destinationConnectionID.encode(to: &writer)
        sourceConnectionID.encode(to: &writer)
        for version in versions {
            writer.writeUInt32(version.rawValue)
        }
        return writer.finishArray()
    }

    private func malformedAuthenticatedShortPacket(
        destinationConnectionID: ConnectionID,
        packetNumber: UInt64 = 0
    ) throws -> [UInt8] {
        let protector = try applicationProtector()
        let header = try ShortHeader(
            destinationConnectionID: destinationConnectionID,
            packetNumber: packetNumber,
            packetNumberLength: 4
        )
        let packetNumberBytes: [UInt8] = [
            UInt8(truncatingIfNeeded: packetNumber >> 24),
            UInt8(truncatingIfNeeded: packetNumber >> 16),
            UInt8(truncatingIfNeeded: packetNumber >> 8),
            UInt8(truncatingIfNeeded: packetNumber),
        ]
        var authenticatedHeader = [header.firstByte]
        authenticatedHeader.append(contentsOf: destinationConnectionID.bytes)
        authenticatedHeader.append(contentsOf: packetNumberBytes)

        // 0xff starts an eight-byte frame type but intentionally omits the
        // remaining bytes. AEAD succeeds; frame decoding must be connection-fatal.
        let ciphertext = try protector.seal(
            [0xff].span,
            packetNumber: packetNumber,
            header: authenticatedHeader.span
        )
        var packet = authenticatedHeader
        packet.append(contentsOf: ciphertext)

        let packetNumberOffset = 1 + destinationConnectionID.bytes.count
        let sampleOffset = packetNumberOffset + 4
        let protected = try protector.applyHeaderProtection(
            sample: packet.span.extracting(sampleOffset..<(sampleOffset + 16)),
            firstByte: header.firstByte,
            packetNumberBytes: packetNumberBytes
        )
        packet[0] = protected.firstByte
        packet.replaceSubrange(
            packetNumberOffset..<(packetNumberOffset + 4),
            with: protected.packetNumberBytes
        )
        return packet
    }

    private func forgedShortPacket(
        destinationConnectionID: ConnectionID,
        packetNumber: UInt64,
        secretByte: UInt8
    ) throws -> [UInt8] {
        let protector = try applicationProtector(secretByte: secretByte)
        var packet = try PacketParsingCore.serializeShortHeaderPacket(
            frames: [.ping],
            header: try ShortHeader(
                destinationConnectionID: destinationConnectionID,
                packetNumber: packetNumber,
                packetNumberLength: 4
            ),
            packetNumber: packetNumber,
            protector: protector,
            headerProtectionProtector: protector
        )
        packet[packet.count - 1] ^= 0x01
        return packet
    }

    // MARK: - Construction

    @Test("engine constructs and installs Initial keys")
    func constructsWithInitialKeys() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))
        let engine = try Engine(configuration: makeConfig(role: .client, dcid: dcid, scid: scid), nowNanos: 0)
        #expect(!engine.isEstablished)
        #expect(!engine.isClosed)
        #expect(engine.currentKeyPhase == 0)
    }

    @Test("RFC-default peer parameters grant no stream credit")
    func absentPeerFlowControlCredit() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))
        var engine = try Engine(
            configuration: makeConfig(role: .client, dcid: dcid, scid: scid),
            nowNanos: 0
        )
        var peer = TransportParametersCore()
        peer.initialSourceConnectionID = dcid
        peer.originalDestinationConnectionID = dcid
        try engine.validateAndApplyPeerTransportParameters(peer)

        #expect(throws: QUICEngineError.self) {
            _ = try engine.openStream(bidirectional: true)
        }
    }

    @Test("server rejects every server-only transport parameter from a client")
    func serverOnlyTransportParametersFromClientFail() throws {
        let clientCID = try #require(ConnectionID.random(length: 8))
        let serverCID = try #require(ConnectionID.random(length: 8))
        var engine = try Engine(
            configuration: makeConfig(role: .server, dcid: clientCID, scid: serverCID),
            nowNanos: 0
        )
        var peer = TransportParametersCore()
        peer.initialSourceConnectionID = clientCID
        peer.statelessResetToken = [UInt8](repeating: 0, count: 16)

        #expect(throws: QUICEngineError.self) {
            try engine.validateAndApplyPeerTransportParameters(peer)
        }
    }

    @Test("connection IDs rotate on one path and retirement is acknowledged")
    func connectionIDRotationRoundTrip() throws {
        var (client, server, _, _, _) = try makePair()
        server.antiAmplification.validateAddress()
        let serverCID1 = try #require(ConnectionID.random(length: 8))
        let serverCID2 = try #require(ConnectionID.random(length: 8))

        try server.issueLocalConnectionID(
            sequenceNumber: 1,
            connectionID: serverCID1,
            statelessResetToken: [UInt8](repeating: 0x11, count: 16)
        )
        for datagram in try server.flush(nowNanos: 1_000) {
            _ = try client.receive(datagram: datagram, nowNanos: 2_000)
        }
        #expect(client.peerConnectionIDs.activeCount == 2)

        try server.issueLocalConnectionID(
            sequenceNumber: 2,
            connectionID: serverCID2,
            statelessResetToken: [UInt8](repeating: 0x22, count: 16),
            retirePriorTo: 1
        )
        var retireAcknowledgements: [[UInt8]] = []
        for datagram in try server.flush(nowNanos: 3_000) {
            let output = try client.receive(datagram: datagram, nowNanos: 4_000)
            retireAcknowledgements.append(contentsOf: output.datagramsToSend)
        }

        #expect(client.currentDestinationConnectionID == serverCID1)
        #expect(client.peerConnectionIDs.activeCount == 2)
        #expect(!retireAcknowledgements.isEmpty)
        for datagram in retireAcknowledgements {
            _ = try server.receive(datagram: datagram, nowNanos: 5_000)
        }
        #expect(server.localConnectionIDs.record(sequenceNumber: 0)?.isRetired == true)
        #expect(server.sourceConnectionID == serverCID1)
    }

    @Test("stateless reset token closes only after packet protection fails")
    func statelessResetDetection() throws {
        var (client, _, _, _, _) = try makePair()
        let token = [UInt8](repeating: 0xA7, count: 16)
        var peerParameters = TransportParametersCore()
        peerParameters.statelessResetToken = token
        client.applyPeerTransportParameters(peerParameters)

        var reset = [UInt8](repeating: 0x5A, count: 24)
        reset[0] = 0x40
        reset.replaceSubrange((reset.count - token.count)..<reset.count, with: token)
        let output = try client.receive(datagram: reset, nowNanos: 10_000)

        #expect(output.peerClosed)
        #expect(client.isClosed)
    }

    @Test("unsupported version with no salt throws")
    func unsupportedVersionThrows() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))
        var cfg = makeConfig(role: .client, dcid: dcid, scid: scid)
        cfg.version = QUICVersion(rawValue: 0xDEADBEEF)  // no initial salt
        #expect(throws: QUICEngineError.self) {
            _ = try Engine(configuration: cfg, nowNanos: 0)
        }
    }

    // MARK: - Clock-free idle timeout

    @Test("idle timeout fires via handleTimeout with injected time (no real sleep)")
    func idleTimeoutClockFree() throws {
        let idle: UInt64 = 1_000_000_000  // 1s
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8)), idleNanos: idle), nowNanos: 0)

        // Before the deadline: not expired.
        var out = try engine.handleTimeout(nowNanos: idle - 1)
        #expect(!out.idleExpired)

        // At/after the deadline: expired, terminal, surfaced to the facade.
        out = try engine.handleTimeout(nowNanos: idle + 1)
        #expect(out.idleExpired)
        #expect(out.firedTimers.contains(.idle))
    }

    @Test("idle deadline is reported in the deadline set")
    func idleDeadlineReported() throws {
        let idle: UInt64 = 5_000_000_000
        let engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8)), idleNanos: idle), nowNanos: 0)
        let deadlines = engine.deadlines(nowNanos: 0)
        #expect(deadlines.idleNanos != nil)
        // The earliest deadline should be the idle one (nothing else armed yet).
        #expect(deadlines.earliestDeadlineNanos == deadlines.idleNanos)
    }

    @Test("idle disabled when timeout is zero")
    func idleDisabled() throws {
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8)), idleNanos: 0), nowNanos: 0)
        let deadlines = engine.deadlines(nowNanos: 0)
        #expect(deadlines.idleNanos == nil)
        let out = try engine.handleTimeout(nowNanos: 100_000_000_000)
        #expect(!out.idleExpired)
    }

    // MARK: - Streams + round-trip over Initial keys (sans-IO)

    @Test("client opens a stream, writes data; server receives it across the sans-IO boundary")
    func streamRoundTripOverInitial() throws {
        var (client, server, _, _, _) = try makePair()

        // Client opens a bidi stream and writes.
        let sid = try client.openStream(bidirectional: true)
        let payload: [UInt8] = Array("hello quic engine".utf8)
        try client.writeStream(sid, data: payload)

        // Flush produces an Initial datagram (we have only Initial keys here).
        let datagrams = try client.flush(nowNanos: 1_000)
        #expect(!datagrams.isEmpty)

        // Server receives the datagram (sans-IO): it decrypts with the shared
        // Initial keys, routes the STREAM frame to the receive core, surfaces the
        // new stream + readable event.
        var sawStream = false
        var received: [UInt8] = []
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            if out.newStreams.contains(sid) { sawStream = true }
            if out.readableStreams.contains(sid) {
                if let data = server.readStream(sid) { received.append(contentsOf: data) }
            }
        }
        #expect(sawStream)
        #expect(received == payload)
    }

    @Test("server ACKs an ack-eliciting packet; client processes the ACK")
    func ackGenerationAndProcessing() throws {
        var (client, server, _, _, _) = try makePair()

        let sid = try client.openStream(bidirectional: true)
        try client.writeStream(sid, data: Array("ping".utf8))
        let datagrams = try client.flush(nowNanos: 1_000)

        // Server receives → owes an ACK; its receive() flush should carry it.
        var serverAck: [[UInt8]] = []
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            serverAck.append(contentsOf: out.datagramsToSend)
            _ = server.readStream(sid)
        }
        // The server may not have new info worth ACKing immediately in the same
        // step; force a flush to emit the owed ACK.
        let forced = try server.flush(nowNanos: 3_000)
        serverAck.append(contentsOf: forced)
        #expect(!serverAck.isEmpty)

        // Client processes the server's ACK without error.
        for dgram in serverAck {
            _ = try client.receive(datagram: dgram, nowNanos: 4_000)
        }
    }

    @Test("RESET_STREAM_AT delivers its reliable prefix through the engine path")
    func resetStreamAtDeliversReliablePrefix() throws {
        var (client, server, _, _, _) = try makePair()
        let streamID = try client.openStream(bidirectional: true)
        try client.writeStream(streamID, data: [1, 2, 3, 4, 5])
        try client.resetStreamAt(
            streamID,
            errorCode: 9,
            reliableSize: 3
        )

        let datagrams = try client.flush(nowNanos: 1_000)
        #expect(!datagrams.isEmpty)

        var received: [UInt8] = []
        for datagram in datagrams {
            _ = try server.receive(datagram: datagram, nowNanos: 2_000)
            if let chunk = server.readStream(streamID) {
                received.append(contentsOf: chunk)
            }
        }

        #expect(received == [1, 2, 3])
        #expect(server.streamReadFinished(streamID))
    }

    @Test("a lost STREAM frame is retransmitted after a later packet is acknowledged")
    func lostStreamFrameIsRetransmitted() throws {
        var (client, server, _, _, _) = try makePair()
        let streamID = try client.openStream(bidirectional: true)
        let payload = Array("retransmit me".utf8)
        try client.writeStream(streamID, data: payload)

        // Drop packet 0, then let a PTO PING create packet 1.
        let dropped = try client.flush(nowNanos: 0)
        #expect(!dropped.isEmpty)
        let pto = try #require(client.deadlines(nowNanos: 0).lossDetectionNanos)
        let probeOutput = try client.handleTimeout(nowNanos: pto + 1)
        #expect(!probeOutput.datagramsToSend.isEmpty)

        // Deliver only the later probe and return its ACK. The ACK makes the
        // older STREAM packet time-threshold lost and the receive tail flushes
        // the ledger-restored STREAM frame.
        var acknowledgements: [[UInt8]] = []
        for probe in probeOutput.datagramsToSend {
            let output = try server.receive(datagram: probe, nowNanos: pto + 2)
            acknowledgements.append(contentsOf: output.datagramsToSend)
        }
        acknowledgements.append(contentsOf: try server.flush(nowNanos: pto + 3))
        #expect(!acknowledgements.isEmpty)

        var retransmissions: [[UInt8]] = []
        for acknowledgement in acknowledgements {
            let output = try client.receive(
                datagram: acknowledgement,
                nowNanos: pto + 1_000_000_000
            )
            retransmissions.append(contentsOf: output.datagramsToSend)
        }
        #expect(!retransmissions.isEmpty)

        var received: [UInt8] = []
        for retransmission in retransmissions {
            _ = try server.receive(
                datagram: retransmission,
                nowNanos: pto + 1_000_000_001
            )
            if let chunk = server.readStream(streamID) {
                received.append(contentsOf: chunk)
            }
        }
        #expect(received == payload)
    }

    @Test("ACK delay conversion honors transport parameter exponent")
    func ackDelayConversionHonorsTransportParameterExponent() {
        #expect(Engine.ackDelayWireUnits(delayNanos: 10_000_000, exponent: 3) == 1_250)
        #expect(Engine.ackDelayNanos(wireUnits: 1_250, exponent: 3) == 10_000_000)
        #expect(Engine.ackDelayNanos(wireUnits: 1, exponent: 10) == 1_024_000)
    }

    @Test("peer ACK transport parameters update RTT and PTO inputs")
    func peerAckTransportParametersUpdateRTTAndPTOInputs() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: dcid, scid: scid), nowNanos: 0)

        var peerTP = TransportParametersCore()
        peerTP.ackDelayExponent = 10
        peerTP.maxAckDelay = 100

        engine.applyPeerTransportParameters(peerTP)

        #expect(engine.peerAckDelayExponent == 10)
        #expect(engine.peerMaxAckDelayNanos == 100_000_000)
    }

    @Test("ACK delay measures from largest acknowledged packet receive time")
    func ackDelayMeasuresFromLargestAcknowledgedReceiveTime() {
        var space = PacketNumberSpace()

        space.recordReceived(packetNumber: 1, ackEliciting: true, nowNanos: 1_000)
        space.recordReceived(packetNumber: 3, ackEliciting: true, nowNanos: 9_000)

        #expect(space.largestReceived == 3)
        #expect(space.largestReceivedTimeNanos == 9_000)
    }

    // MARK: - Clock-free PTO probe

    @Test("PTO probe is produced via handleTimeout after an ack-eliciting send (clock-free)")
    func ptoProbeClockFree() throws {
        var (client, _, _, _, _) = try makePair()

        let sid = try client.openStream(bidirectional: true)
        try client.writeStream(sid, data: Array("data".utf8))
        // Send at t=0 (ack-eliciting packet now in flight).
        let sent = try client.flush(nowNanos: 0)
        #expect(!sent.isEmpty)

        // A loss-detection (PTO) deadline must now be armed.
        let deadlines = client.deadlines(nowNanos: 0)
        let pto = try #require(deadlines.lossDetectionNanos)
        #expect(pto > 0)

        // Drive the timer far past the PTO deadline: a probe (ack-eliciting
        // packet) is produced and the PTO fired — with NO real sleep.
        let out = try client.handleTimeout(nowNanos: pto + 1_000_000_000)
        #expect(out.firedTimers.contains(.lossDetection))
        #expect(!out.datagramsToSend.isEmpty)
    }

    @Test("no PTO deadline armed when nothing is in flight")
    func noPTOWhenIdle() throws {
        let (client, _, _, _, _) = try makePair()
        let deadlines = client.deadlines(nowNanos: 0)
        #expect(deadlines.lossDetectionNanos == nil)
    }

    // MARK: - Connection close

    @Test("close produces a CONNECTION_CLOSE and marks the engine closed")
    func closeProducesConnectionClose() throws {
        var (client, server, _, _, _) = try makePair()

        client.close(errorCode: 0, reason: Array("bye".utf8), isApplicationError: false)
        let datagrams = try client.flush(nowNanos: 1_000)
        #expect(!datagrams.isEmpty)
        #expect(client.isClosed)

        // Server sees the peer close.
        var peerClosed = false
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            if out.peerClosed { peerClosed = true }
        }
        #expect(peerClosed)
        #expect(server.isClosed)
    }

    @Test("operations after close throw connectionClosed")
    func operationsAfterCloseThrow() throws {
        var (client, _, _, _, _) = try makePair()
        client.close(errorCode: 0, reason: [], isApplicationError: false)
        _ = try client.flush(nowNanos: 1_000)
        #expect(client.isClosed)
        #expect(throws: QUICEngineError.self) {
            _ = try client.openStream(bidirectional: true)
        }
    }

    // MARK: - Key update (RFC 9001 §6)

    @Test("application key update flips the key phase deterministically")
    func keyUpdateFlipsPhase() throws {
        var engine = try Engine(configuration: makeConfig(role: .server, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8))), nowNanos: 0)
        // Install application keys (32-byte traffic secrets), then update.
        let readSecret = [UInt8](repeating: 0x01, count: 32)
        let writeSecret = [UInt8](repeating: 0x02, count: 32)
        try engine.installKeys(level: .application, readSecret: readSecret, writeSecret: writeSecret, suite: .aes128GCM)
        engine.markHandshakeComplete()
        #expect(engine.currentKeyPhase == 0)
        let newPhase = try engine.performKeyUpdate()
        #expect(newPhase == 1)
        #expect(engine.currentKeyPhase == 1)
        // A subsequent update is rejected until a current-phase packet is ACKed.
        #expect(throws: QUICEngineError.self) {
            _ = try engine.performKeyUpdate()
        }
    }

    @Test("AES confidentiality limit advances application write keys before reuse")
    func confidentialityLimitTriggersKeyUpdate() throws {
        let limits = QUICAEADUsageLimits(aesGCMConfidentialityPackets: 1)
        var (client, _, _, _, _) = try makePair(aeadUsageLimits: limits)
        let streamID = try client.openStream(bidirectional: true)

        try client.writeStream(streamID, data: [0x01])
        #expect(!(try client.flush(nowNanos: 1_000)).isEmpty)
        #expect(client.currentKeyPhase == 0)

        try client.writeStream(streamID, data: [0x02])
        #expect(!(try client.flush(nowNanos: 2_000)).isEmpty)
        #expect(client.currentKeyPhase == 1)
        #expect(client.keys.writePacketCount(for: .application) == 1)
    }

    @Test("authentication failures close the connection after the integrity limit")
    func integrityFailureLimitClosesConnection() throws {
        let limits = QUICAEADUsageLimits(
            aesGCMConfidentialityPackets: 8_388_608,
            aesGCMIntegrityFailures: 1
        )
        var (client, _, _, clientSCID, _) = try makePair(aeadUsageLimits: limits)
        let first = try forgedShortPacket(
            destinationConnectionID: clientSCID,
            packetNumber: 0,
            secretByte: 0x05
        )
        let second = try forgedShortPacket(
            destinationConnectionID: clientSCID,
            packetNumber: 1,
            secretByte: 0x05
        )

        _ = try client.receive(datagram: first, nowNanos: 1_000)
        #expect(!client.isClosed)
        do {
            _ = try client.receive(datagram: second, nowNanos: 2_000)
            Issue.record("the second authentication failure must reach the configured integrity limit")
        } catch QUICEngineError.aeadLimitReached {
            #expect(client.isClosed)
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test("separately delivered application secrets remain available for key update")
    func separatelyInstalledApplicationSecretsRemainAvailable() throws {
        var engine = try Engine(
            configuration: makeConfig(
                role: .server,
                dcid: try #require(ConnectionID.random(length: 8)),
                scid: try #require(ConnectionID.random(length: 8))
            ),
            nowNanos: 0
        )
        let readSecret = [UInt8](repeating: 0x01, count: 32)
        let writeSecret = [UInt8](repeating: 0x02, count: 32)

        try engine.installKeys(
            level: .application,
            readSecret: readSecret,
            writeSecret: nil,
            suite: .aes128GCM
        )
        try engine.installKeys(
            level: .application,
            readSecret: nil,
            writeSecret: writeSecret,
            suite: .aes128GCM
        )

        engine.markHandshakeComplete()

        #expect(try engine.performKeyUpdate() == 1)
    }

    @Test("peer key update commits after AEAD and retains reordered previous keys")
    func peerKeyUpdateAndReorderedPreviousPacket() throws {
        var (client, server, _, _, _) = try makePair()
        let streamID = try client.openStream(bidirectional: true)

        // Hold one phase-0 packet so it arrives after the phase-1 transition.
        try client.writeStream(streamID, data: [0, 1, 2])
        let delayedOldPackets = try client.flush(nowNanos: 1_000)
        #expect(!delayedOldPackets.isEmpty)

        #expect(try client.performKeyUpdate() == 1)
        try client.writeStream(streamID, data: [3, 4, 5])
        let updatedPackets = try client.flush(nowNanos: 2_000)
        #expect(!updatedPackets.isEmpty)

        var acknowledgements: [[UInt8]] = []
        for packet in updatedPackets {
            let output = try server.receive(datagram: packet, nowNanos: 3_000)
            acknowledgements.append(contentsOf: output.datagramsToSend)
        }
        #expect(server.currentKeyPhase == 1)

        // Packet number zero with the prior phase remains decryptable after
        // packet number one commits the next receive generation.
        for packet in delayedOldPackets {
            let output = try server.receive(datagram: packet, nowNanos: 4_000)
            acknowledgements.append(contentsOf: output.datagramsToSend)
        }
        #expect(server.keys.hasPreviousReadGeneration)
        let discardDeadline = try #require(
            server.deadlines(nowNanos: 4_000).keyDiscardNanos
        )
        let timerOutput = try server.handleTimeout(nowNanos: discardDeadline)
        acknowledgements.append(contentsOf: timerOutput.datagramsToSend)
        #expect(timerOutput.firedTimers.contains(.keyDiscard))
        #expect(!server.keys.hasPreviousReadGeneration)
        acknowledgements.append(contentsOf: try server.flush(nowNanos: 5_000))
        #expect(server.readStream(streamID) == [0, 1, 2, 3, 4, 5])

        for packet in acknowledgements {
            _ = try client.receive(datagram: packet, nowNanos: 6_000)
        }

        // The phase-1 ACK both commits the client's read generation and permits
        // the next locally initiated update.
        #expect(try client.performKeyUpdate() == 0)
    }

    @Test("authenticated malformed frames are fatal but forged packets are dropped")
    func authenticatedMalformedFrameIsFatal() throws {
        var (_, server, _, _, serverSCID) = try makePair()
        let malformed = try malformedAuthenticatedShortPacket(
            destinationConnectionID: serverSCID
        )
        #expect(throws: QUICEngineError.self) {
            _ = try server.receive(datagram: malformed, nowNanos: 1_000)
        }

        var forged = malformed
        forged[forged.count - 1] ^= 0x01
        _ = try server.receive(datagram: forged, nowNanos: 2_000)
    }

    @Test("STREAM end-offset overflow is rejected")
    func streamEndOffsetOverflowIsRejected() throws {
        var (_, server, _, _, serverSCID) = try makePair()
        let protector = try applicationProtector()
        let packet = try PacketParsingCore.serializeShortHeaderPacket(
            frames: [
                .stream(StreamFrame(
                    streamID: 0,
                    offset: Varint.maxValue,
                    data: [1]
                )),
            ],
            header: try ShortHeader(
                destinationConnectionID: serverSCID,
                packetNumber: 0,
                packetNumberLength: 4
            ),
            packetNumber: 0,
            protector: protector
        )

        #expect(throws: QUICEngineError.self) {
            _ = try server.receive(datagram: packet, nowNanos: 1_000)
        }
    }

    @Test("authenticated packets for an inactive destination CID are dropped")
    func inactiveDestinationConnectionIDIsDropped() throws {
        var (_, server, _, _, _) = try makePair()
        let protector = try applicationProtector()
        let inactiveCID = try #require(ConnectionID.random(length: 8))
        let packet = try PacketParsingCore.serializeShortHeaderPacket(
            frames: [.ping],
            header: try ShortHeader(
                destinationConnectionID: inactiveCID,
                packetNumber: 0,
                packetNumberLength: 4
            ),
            packetNumber: 0,
            protector: protector
        )

        let output = try server.receive(datagram: packet, nowNanos: 1_000)
        #expect(output.newStreams.isEmpty)
        #expect(server.applicationSpace.largestReceived == nil)
    }

    @Test("key update before application keys are installed throws")
    func keyUpdateBeforeKeysThrows() throws {
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8))), nowNanos: 0)
        #expect(throws: QUICEngineError.self) {
            _ = try engine.performKeyUpdate()
        }
    }

    // MARK: - Anti-amplification (RFC 9000 §8.1)

    @Test("server is anti-amplification blocked before receiving enough bytes")
    func serverAntiAmplification() throws {
        var (_, server, _, _, _) = try makePair()
        // Server has received nothing → its 3x budget is 0; an Initial flush
        // produces nothing (blocked) rather than amplifying.
        server.queueHandshake(Array(repeating: 0xAB, count: 100), level: .initial)
        let datagrams = try server.flush(nowNanos: 1_000)
        #expect(datagrams.isEmpty)
    }

    @Test("valid Retry replays the original Initial CRYPTO with token and new keys")
    func validRetryReplaysInitialCrypto() throws {
        let originalDestination = try #require(ConnectionID.random(length: 8))
        let clientSource = try #require(ConnectionID.random(length: 8))
        let retrySource = try #require(ConnectionID.random(length: 8))
        var client = try Engine(
            configuration: makeConfig(
                role: .client,
                dcid: originalDestination,
                scid: clientSource
            ),
            nowNanos: 0
        )
        let clientHello: [UInt8] = [0x01, 0x00, 0x00, 0x01, 0xaa]
        client.queueHandshake(clientHello, level: .initial)
        #expect(!(try client.flush(nowNanos: 1)).isEmpty)

        let token: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
        let retry = try retryPacket(
            originalDestinationConnectionID: originalDestination,
            destinationConnectionID: clientSource,
            sourceConnectionID: retrySource,
            token: token
        )
        let output = try client.receive(datagram: retry, nowNanos: 2)
        let replay = try #require(output.datagramsToSend.first)
        let (protectedHeader, _) = try ProtectedLongHeader.parse(from: replay)
        #expect(protectedHeader.packetType == .initial)
        #expect(protectedHeader.destinationConnectionID == retrySource)
        #expect(protectedHeader.sourceConnectionID == clientSource)
        #expect(protectedHeader.token == token)
        #expect(client.currentDestinationConnectionID == retrySource)

        let salt = try #require(QUICVersion.v1.initialSaltBytes)
        let secrets = try QUICKeyDerivation.initialSecrets(
            connectionID: retrySource.bytes,
            salt: salt
        )
        let serverProtector = try QUICKeyDerivation.protector(
            secret: secrets.client,
            suite: .aes128GCM
        )
        let parsed = try PacketParsingCore.parseLongHeaderPacket(
            bytes: replay.span,
            protector: serverProtector,
            largestPN: 0
        )
        let replayedCrypto = parsed.frames.compactMap { frame -> [UInt8]? in
            guard case .crypto(let crypto) = frame else { return nil }
            return crypto.data
        }
        #expect(replayedCrypto == [clientHello])
    }

    @Test("forged Retry is discarded without changing destination CID")
    func forgedRetryIsDiscarded() throws {
        let originalDestination = try #require(ConnectionID.random(length: 8))
        let clientSource = try #require(ConnectionID.random(length: 8))
        let retrySource = try #require(ConnectionID.random(length: 8))
        var client = try Engine(
            configuration: makeConfig(
                role: .client,
                dcid: originalDestination,
                scid: clientSource
            ),
            nowNanos: 0
        )
        var retry = try retryPacket(
            originalDestinationConnectionID: originalDestination,
            destinationConnectionID: clientSource,
            sourceConnectionID: retrySource,
            token: [0x01]
        )
        retry[retry.count - 1] ^= 0x01
        let output = try client.receive(datagram: retry, nowNanos: 1)
        #expect(output.isEmpty)
        #expect(client.currentDestinationConnectionID == originalDestination)
    }

    @Test("Version Negotiation is validated and surfaced as a typed restart requirement")
    func versionNegotiationIsValidated() throws {
        let originalDestination = try #require(ConnectionID.random(length: 8))
        let clientSource = try #require(ConnectionID.random(length: 8))
        var client = try Engine(
            configuration: makeConfig(
                role: .client,
                dcid: originalDestination,
                scid: clientSource
            ),
            nowNanos: 0
        )

        let downgradeNoise = versionNegotiationPacket(
            destinationConnectionID: clientSource,
            sourceConnectionID: originalDestination,
            versions: [.v1, .v2]
        )
        #expect(try client.receive(datagram: downgradeNoise, nowNanos: 1).isEmpty)

        let negotiation = versionNegotiationPacket(
            destinationConnectionID: clientSource,
            sourceConnectionID: originalDestination,
            versions: [.v2]
        )
        do {
            _ = try client.receive(datagram: negotiation, nowNanos: 2)
            Issue.record("Expected Version Negotiation to require a new connection attempt")
        } catch .versionNegotiationRequired(let versions) {
            #expect(versions == [QUICVersion.v2.rawValue])
        }
    }
}
