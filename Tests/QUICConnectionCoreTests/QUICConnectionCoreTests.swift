import Testing
import QUICWire
@testable import QUICConnectionCore

@Suite("QUIC connection core")
struct QUICConnectionCoreTests {
    @Test("wire defaults and recommended local settings remain distinct")
    func transportParameterDefaults() {
        let wireDefaults = TransportParametersCore()
        #expect(wireDefaults.maxIdleTimeout == 0)
        #expect(wireDefaults.initialMaxData == 0)
        #expect(wireDefaults.initialMaxStreamsBidi == 0)
        #expect(wireDefaults.initialMaxStreamsUni == 0)
        #expect(wireDefaults.maxUDPPayloadSize == 65_527)

        let local = TransportParametersCore.recommendedLocal()
        #expect(local.maxIdleTimeout == 30_000)
        #expect(local.initialMaxData == 10_000_000)
        #expect(local.initialMaxStreamsBidi == 100)
        #expect(local.initialMaxStreamsUni == 100)
    }

    @Test("transport parameters round trip every supported field")
    func transportParameterRoundTrip() throws {
        let sourceCID = try ConnectionID(bytes: [1, 2, 3, 4])
        let originalCID = try ConnectionID(bytes: [5, 6, 7, 8])
        let preferredCID = try ConnectionID(bytes: [9, 10, 11, 12])
        var parameters = TransportParametersCore.recommendedLocal()
        parameters.originalDestinationConnectionID = originalCID
        parameters.statelessResetToken = [UInt8](repeating: 0xAA, count: 16)
        parameters.maxUDPPayloadSize = 1_450
        parameters.ackDelayExponent = 7
        parameters.maxAckDelay = 40
        parameters.disableActiveMigration = true
        parameters.activeConnectionIDLimit = 5
        parameters.initialSourceConnectionID = sourceCID
        parameters.enableResetStreamAt = true
        parameters.maxDatagramFrameSize = 1_200
        parameters.preferredAddress = PreferredAddressCore(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 12),
            ipv6Port: 8443,
            connectionID: preferredCID,
            statelessResetToken: [UInt8](repeating: 0xBB, count: 16)
        )

        let encoded = try TransportParameterCodecCore.encode(parameters)
        let decoded = try TransportParameterCodecCore.decode(encoded)
        #expect(decoded == parameters)
    }

    @Test("empty peer parameters decode to RFC zero-credit defaults")
    func emptyTransportParameters() throws {
        let decoded = try TransportParameterCodecCore.decode([])
        #expect(decoded.initialMaxData == 0)
        #expect(decoded.initialMaxStreamDataBidiLocal == 0)
        #expect(decoded.initialMaxStreamDataBidiRemote == 0)
        #expect(decoded.initialMaxStreamDataUni == 0)
        #expect(decoded.initialMaxStreamsBidi == 0)
        #expect(decoded.initialMaxStreamsUni == 0)
    }

    @Test("transport parameter decoder rejects duplicates trailing bytes and excess stream counts")
    func invalidTransportParameterWireValues() throws {
        #expect(throws: TransportParameterCodecError.duplicateParameter(1)) {
            try TransportParameterCodecCore.decode([1, 1, 0, 1, 1, 0])
        }
        #expect(throws: TransportParameterCodecError.decodeError(
            "Trailing bytes after transport parameter varint"
        )) {
            try TransportParameterCodecCore.decode([1, 2, 0, 0])
        }

        var writer = QUICWireWriter()
        try writer.writeVarint(TransportParameterIDCore.initialMaxStreamsBidi.rawValue)
        let invalidCount = (UInt64(1) << 60) + 1
        try writer.writeVarint(UInt64(Varint.encodedLength(for: invalidCount)))
        try writer.writeVarint(invalidCount)
        #expect(throws: TransportParameterCodecError.self) {
            try TransportParameterCodecCore.decode(writer.finishArray())
        }
    }

    @Test("transport parameter encoder fails closed on malformed local values")
    func invalidTransportParameterLocalValues() throws {
        var parameters = TransportParametersCore()
        parameters.statelessResetToken = [0]
        #expect(throws: TransportParameterCodecError.self) {
            try TransportParameterCodecCore.encode(parameters)
        }

        parameters.statelessResetToken = nil
        parameters.preferredAddress = PreferredAddressCore(
            ipv4Address: [127, 0, 0, 1],
            ipv4Port: nil,
            connectionID: try ConnectionID(bytes: [1]),
            statelessResetToken: [UInt8](repeating: 0, count: 16)
        )
        #expect(throws: TransportParameterCodecError.self) {
            try TransportParameterCodecCore.encode(parameters)
        }
    }

    @Test("IP codecs use strict IPv4 and canonical IPv6 forms")
    func ipAddressCodec() {
        #expect(IPAddressCodec.parseIPv4("192.0.2.1") == [192, 0, 2, 1])
        #expect(IPAddressCodec.formatIPv4([203, 0, 113, 9]) == "203.0.113.9")
        #expect(IPAddressCodec.parseIPv4("01.2.3.4") == nil)
        #expect(IPAddressCodec.parseIPv4("256.0.0.1") == nil)
        #expect(IPAddressCodec.formatIPv4([1, 2, 3]) == nil)

        let bytes = IPAddressCodec.parseIPv6("2001:0db8:0:0:0:0:0:1")
        #expect(bytes != nil)
        #expect(bytes.flatMap(IPAddressCodec.formatIPv6) == "2001:db8::1")
        #expect(IPAddressCodec.parseIPv6("2001::db8::1") == nil)
        #expect(IPAddressCodec.parseIPv6("fe80::1%en0") == nil)
        #expect(IPAddressCodec.formatIPv6([UInt8](repeating: 0, count: 15)) == nil)
    }

    @Test("coalesced splitter returns borrowed packet ranges in wire order")
    func coalescedPacketRanges() throws {
        let initial = try longPacket(firstByte: 0xC0, payload: 0x11, includesToken: true)
        let handshake = try longPacket(firstByte: 0xE0, payload: 0x22, includesToken: false)
        let datagram = initial + handshake

        let ranges = try CoalescedDatagramCore.split(datagram: datagram.span, dcidLength: 0)
        #expect(ranges == [
            CoalescedPacketRange(isLongHeader: true, offset: 0, length: initial.count),
            CoalescedPacketRange(
                isLongHeader: true,
                offset: initial.count,
                length: handshake.count
            ),
        ])
    }

    @Test("coalesced splitter rejects empty truncated and malformed headers")
    func coalescedPacketValidation() throws {
        #expect(throws: CoalescedDatagramError.emptyDatagram) {
            try CoalescedDatagramCore.split(datagram: [UInt8]().span, dcidLength: 0)
        }
        #expect(throws: CoalescedDatagramError.insufficientData) {
            try CoalescedDatagramCore.split(datagram: [0x40, 0].span, dcidLength: 8)
        }
        #expect(throws: CoalescedDatagramError.invalidPacketHeader) {
            try CoalescedDatagramCore.split(datagram: [0x40, 0].span, dcidLength: 21)
        }

        var truncated = QUICWireWriter()
        truncated.writeByte(0xE0)
        truncated.writeUInt32(QUICVersion.v1.rawValue)
        truncated.writeByte(0)
        truncated.writeByte(0)
        try truncated.writeVarint(10)
        truncated.writeByte(0)
        #expect(throws: CoalescedDatagramError.packetLengthExceedsDatagram) {
            try CoalescedDatagramCore.split(
                datagram: truncated.finishArray().span,
                dcidLength: 0
            )
        }

        var oversizedCID = QUICWireWriter()
        oversizedCID.writeByte(0xC0)
        oversizedCID.writeUInt32(QUICVersion.v1.rawValue)
        oversizedCID.writeByte(21)
        oversizedCID.writeBytes([UInt8](repeating: 0, count: 21))
        #expect(throws: CoalescedDatagramError.invalidPacketHeader) {
            try CoalescedDatagramCore.split(
                datagram: oversizedCID.finishArray().span,
                dcidLength: 0
            )
        }
    }

    @Test("connection state isolates packet-number spaces and lifecycle transitions")
    func connectionStateLifecycle() throws {
        let local = try ConnectionID(bytes: [1])
        let peer = try ConnectionID(bytes: [2])
        var state = ConnectionStateCore(
            role: .client,
            version: .v1,
            sourceConnectionID: local,
            destinationConnectionID: peer
        )

        #expect(try state.getNextPacketNumber(for: .initial) == 0)
        #expect(try state.getNextPacketNumber(for: .initial) == 1)
        #expect(try state.getNextPacketNumber(for: .handshake) == 0)
        state.updateLargestReceived(4, level: .application)
        state.updateLargestReceived(2, level: .application)
        #expect(state.largestReceived(for: .application) == 4)

        state.handshakeConfirmed()
        #expect(state.status == .established)
        state.closeReceived()
        #expect(state.status == .draining)
        state.markClosed()
        #expect(state.status == .closed)
        #expect(state.drainDeadlineNanos(closeStartedNanos: 100, ptoNanos: 20) == 160)
        #expect(state.drainDeadlineNanos(
            closeStartedNanos: UInt64.max - 1,
            ptoNanos: UInt64.max
        ) == UInt64.max)
    }

    @Test("idle timeout negotiates deadlines keep-alive and terminal state")
    func idleTimeoutLifecycle() {
        var idle = IdleTimeoutCore(localTimeoutNanos: 100, nowNanos: 10)
        idle.setPeerTimeout(80)
        idle.setKeepAlive(enabled: true)
        #expect(idle.effectiveTimeoutNanos == 80)
        #expect(idle.nextDeadlineNanos() == 50)
        #expect(!idle.shouldSendKeepAlive(nowNanos: 49))
        #expect(idle.shouldSendKeepAlive(nowNanos: 50))

        idle.recordActivity(nowNanos: 20)
        #expect(idle.timeUntilTimeoutNanos(nowNanos: 99) == 1)
        let didTimeOut = idle.checkTimeout(nowNanos: 100)
        #expect(didTimeOut)
        #expect(idle.currentState == .timedOut)
        #expect(idle.nextDeadlineNanos() == nil)

        var saturated = IdleTimeoutCore(localTimeoutNanos: 10, nowNanos: UInt64.max - 2)
        #expect(saturated.nextDeadlineNanos() == UInt64.max)
        let timedOutBeforeSaturatedDeadline = saturated.checkTimeout(nowNanos: UInt64.max - 1)
        #expect(!timedOutBeforeSaturatedDeadline)
        let timedOutAtSaturatedDeadline = saturated.checkTimeout(nowNanos: UInt64.max)
        #expect(timedOutAtSaturatedDeadline)
    }

    @Test("path validation is exact-match fail-closed and expires at its deadline")
    func pathValidationLifecycle() {
        let path = PathValidationCore.NetworkPath(
            localAddress: "192.0.2.1:443",
            remoteAddress: "198.51.100.2:443"
        )
        var validation = PathValidationCore(validationTimeoutNanos: 10)
        let original = [UInt8](repeating: 1, count: 8)
        let replacement = [UInt8](repeating: 2, count: 8)

        validation.startValidation(challengeData: original, for: path, nowNanos: 0)
        validation.startValidation(challengeData: replacement, for: path, nowNanos: 1)
        let staleResponse = validation.handleResponse(original, nowNanos: 2)
        #expect(staleResponse == nil)
        #expect(!validation.isValidated(path))
        let beforeDeadline = validation.checkTimeouts(nowNanos: 10)
        #expect(beforeDeadline.isEmpty)
        let expired = validation.checkTimeouts(nowNanos: 11)
        #expect(expired == [path])
        #expect(validation.validationState(for: path) == .failed(reason: .timeout))
        let didRetry = validation.retryValidation(
            challengeData: replacement,
            for: path,
            nowNanos: 12
        )
        #expect(didRetry)
        let validatedPath = validation.handleResponse(replacement, nowNanos: 13)
        #expect(validatedPath == path)
        #expect(validation.isValidated(path))
    }

    @Test("path challenge response is deferred when amplification budget is insufficient")
    func pathChallengeBudget() {
        let path = PathValidationCore.NetworkPath(localAddress: "local", remoteAddress: "peer")
        let challenge = [UInt8](repeating: 3, count: 8)
        var validation = PathValidationCore(validationTimeoutNanos: 10)

        #expect(validation.handleChallenge(
            challenge,
            on: path,
            remainingAmplificationBudget: 8
        ) == nil)
        #expect(validation.takePendingResponsesWithPaths() == [
            PathValidationCore.PendingResponse(data: challenge, path: path),
        ])
        #expect(validation.handleChallenge(
            challenge,
            on: path,
            remainingAmplificationBudget: 9
        ) == challenge)
    }

    @Test("PMTU search retries a lost target before lowering its ceiling")
    func pathMTUSearch() {
        var search = PathMTUSearchCore(enabled: true, maxProbeSize: 1_500)
        #expect(search.nextProbeSize() == 1_350)

        for packetNumber in UInt64(1)...UInt64(2) {
            search.recordProbeSent(size: 1_350, packetNumber: packetNumber)
            let matched = search.onProbeLost(packetNumber: packetNumber)
            #expect(matched)
            #expect(search.nextProbeSize() == 1_350)
        }
        search.recordProbeSent(size: 1_350, packetNumber: 3)
        let thirdLossMatched = search.onProbeLost(packetNumber: 3)
        #expect(thirdLossMatched)
        #expect(search.maxPLPMTU == 1_349)
        #expect(search.nextProbeSize() == 1_274)

        search.recordProbeSent(size: 1_274, packetNumber: 4)
        let acknowledgementMatched = search.onProbeAcknowledged(packetNumber: 4)
        #expect(acknowledgementMatched)
        #expect(search.currentPLPMTU == 1_274)
        search.reset()
        #expect(search.phase == .base)
        #expect(search.currentPLPMTU == 1_200)
    }

    private func longPacket(
        firstByte: UInt8,
        payload: UInt8,
        includesToken: Bool
    ) throws -> [UInt8] {
        var writer = QUICWireWriter()
        writer.writeByte(firstByte)
        writer.writeUInt32(QUICVersion.v1.rawValue)
        writer.writeByte(0)
        writer.writeByte(0)
        if includesToken {
            try writer.writeVarint(0)
        }
        try writer.writeVarint(1)
        writer.writeByte(payload)
        return writer.finishArray()
    }
}
