import Testing
import QUICWire
@testable import QUICStreamCore

@Suite("QUIC stream core")
struct QUICStreamCoreTests {
    @Test("stream identifiers preserve initiator direction and index")
    func streamIdentifierLayout() {
        let cases: [(UInt64, Bool, Bool, StreamID.StreamType)] = [
            (0, true, true, .clientInitiatedBidirectional),
            (1, false, true, .serverInitiatedBidirectional),
            (2, true, false, .clientInitiatedUnidirectional),
            (3, false, false, .serverInitiatedUnidirectional),
        ]

        for (lowBits, isClient, isBidirectional, expectedType) in cases {
            let id = StreamID.make(
                index: 9,
                isClient: isClient,
                isBidirectional: isBidirectional
            )
            #expect(id == 36 | lowBits)
            #expect(StreamID.streamType(for: id) == expectedType)
            #expect(StreamID.isClientInitiated(id) == isClient)
            #expect(StreamID.isBidirectional(id) == isBidirectional)
        }
    }

    @Test("UInt64 map retains insertion order while updating and removing values")
    func uint64MapOperations() {
        var map = UInt64ValueMap<String>()
        map[7] = "seven"
        map[2] = "two"
        map[7] = "updated"

        #expect(map.count == 2)
        #expect(map.keys == [7, 2])
        #expect(map.values == ["updated", "two"])
        #expect(map.removeValue(forKey: 7) == "updated")
        #expect(map[7] == nil)

        map[2] = nil
        #expect(map.isEmpty)
    }

    @Test("reassembly joins out-of-order adjacent segments and completes FIN")
    func reassemblyOutOfOrder() throws {
        var buffer = StreamReassemblyBuffer(maxBufferSize: 16)
        try buffer.insert(offset: 3, data: [4, 5, 6], fin: true)
        #expect(buffer.hasGap)
        #expect(buffer.finalSize == 6)
        #expect(buffer.readAllContiguous() == nil)

        try buffer.insert(offset: 0, data: [1, 2, 3], fin: false)
        #expect(buffer.segmentCount == 1)
        #expect(buffer.peekContiguous() == [1, 2, 3, 4, 5, 6])
        #expect(buffer.readAllContiguous() == [1, 2, 3, 4, 5, 6])
        #expect(buffer.isComplete)
        #expect(buffer.remainingBytes == 0)
    }

    @Test("identical overlap is idempotent and conflicting overlap is rejected transactionally")
    func reassemblyOverlapContract() throws {
        var buffer = StreamReassemblyBuffer(maxBufferSize: 16)
        try buffer.insert(offset: 0, data: [1, 2, 3, 4], fin: false)
        try buffer.insert(offset: 2, data: [3, 4, 5], fin: false)
        #expect(buffer.bufferedBytes == 5)

        do {
            try buffer.insert(offset: 1, data: [2, 9], fin: false)
            Issue.record("Conflicting overlap was accepted")
        } catch let error {
            guard case .conflictingOverlap(offset: 2) = error else {
                Issue.record("Unexpected overlap error: \(error)")
                return
            }
        }

        #expect(buffer.bufferedBytes == 5)
        #expect(buffer.readAllContiguous() == [1, 2, 3, 4, 5])
    }

    @Test("reassembly rejects final-size violations and buffer exhaustion")
    func reassemblyBounds() throws {
        var finalSizeBuffer = StreamReassemblyBuffer(maxBufferSize: 16)
        try finalSizeBuffer.insert(offset: 0, data: [1, 2, 3], fin: true)
        #expect(throws: DataBufferError.self) {
            try finalSizeBuffer.insert(offset: 0, data: [1, 2], fin: true)
        }
        #expect(throws: DataBufferError.self) {
            try finalSizeBuffer.insert(offset: 3, data: [4], fin: false)
        }
        #expect(throws: DataBufferError.self) {
            try finalSizeBuffer.insert(
                offset: StreamReassemblyBuffer.maxFinalOffset,
                data: [1],
                fin: false
            )
        }

        var bounded = StreamReassemblyBuffer(maxBufferSize: 4)
        try bounded.insert(offset: 0, data: [1, 2, 3, 4], fin: false)
        #expect(throws: DataBufferError.self) {
            try bounded.insert(offset: 4, data: [5], fin: false)
        }
        #expect(bounded.bufferedBytes == 4)
    }

    @Test("send stream obeys flow control and completes after FIN acknowledgement")
    func sendStreamLifecycle() throws {
        var stream = SendStreamCore(id: 0, isLocallyInitiated: true, initialSendMaxData: 3)
        try stream.write([1, 2, 3, 4, 5])
        try stream.finish()

        let first = stream.generateFrames(maxBytes: 64)
        #expect(first.count == 1)
        #expect(first[0].offset == 0)
        #expect(first[0].data == [1, 2, 3])
        #expect(!first[0].fin)
        #expect(stream.sendOffset == 3)
        #expect(stream.pendingSendBytes == 2)

        stream.updateSendMaxData(5)
        let second = stream.generateFrames(maxBytes: 64)
        #expect(second.count == 1)
        #expect(second[0].offset == 3)
        #expect(second[0].data == [4, 5])
        #expect(second[0].fin)
        #expect(stream.sendState == .dataSent)

        stream.acknowledgeData(upTo: 5)
        #expect(stream.sendState == .dataRecvd)
        #expect(stream.isSendClosed)
        #expect(throws: StreamError.self) {
            try stream.write([6])
        }
    }

    @Test("receive-only stream rejects writes and STOP_SENDING produces one reset")
    func sendStreamResetContract() {
        var receiveOnly = SendStreamCore(id: 2, isLocallyInitiated: false, initialSendMaxData: 10)
        #expect(throws: StreamError.self) {
            try receiveOnly.write([1])
        }

        var stream = SendStreamCore(id: 0, isLocallyInitiated: true, initialSendMaxData: 10)
        stream.handleStopSending(errorCode: 42)
        #expect(stream.needsResetStream)
        #expect(stream.stopSendingErrorCode == 42)
        let reset = stream.generateResetStream(errorCode: 42)
        #expect(reset?.streamID == 0)
        #expect(reset?.applicationErrorCode == 42)
        #expect(reset?.finalSize == 0)
        #expect(stream.generateResetStream(errorCode: 42) == nil)
        stream.acknowledgeReset()
        #expect(stream.sendState == .resetRecvd)
    }

    @Test("partial reset waits until the reliable prefix entered the send path")
    func sendStreamPartialReset() throws {
        var stream = SendStreamCore(id: 0, isLocallyInitiated: true, initialSendMaxData: 10)
        try stream.write([1, 2, 3, 4, 5])
        try stream.requestResetStreamAt(errorCode: 9, reliableSize: 3)
        #expect(stream.generateResetStreamAt() == nil)

        let frames = stream.generateFrames(maxBytes: 64)
        #expect(frames.map(\.data) == [[1, 2, 3]])
        let reset = stream.generateResetStreamAt()
        #expect(reset?.applicationErrorCode == 9)
        #expect(reset?.finalSize == 5)
        #expect(reset?.reliableSize == 3)
        #expect(stream.sendState == .resetSent)
    }

    @Test("receive stream reassembles out of order and reaches data-read")
    func receiveStreamLifecycle() throws {
        var stream = ReceiveStreamCore(
            id: 0,
            isLocallyInitiated: true,
            initialRecvMaxData: 10,
            maxBufferSize: 10
        )
        try stream.receive(frame(id: 0, offset: 3, data: [4, 5, 6], fin: true))
        #expect(stream.read() == nil)
        try stream.receive(frame(id: 0, offset: 0, data: [1, 2, 3], fin: false))

        #expect(stream.peek() == [1, 2, 3, 4, 5, 6])
        #expect(stream.read() == [1, 2, 3, 4, 5, 6])
        #expect(stream.recvState == .dataRead)
        #expect(stream.isReceiveClosed)
    }

    @Test("receive stream reports identity direction flow and final-size violations")
    func receiveStreamValidation() throws {
        var stream = ReceiveStreamCore(
            id: 0,
            isLocallyInitiated: true,
            initialRecvMaxData: 4,
            maxBufferSize: 4
        )
        #expect(throws: StreamError.self) {
            try stream.receive(frame(id: 4, offset: 0, data: [1], fin: false))
        }
        #expect(throws: StreamError.self) {
            try stream.receive(frame(id: 0, offset: 4, data: [1], fin: false))
        }

        try stream.receive(frame(id: 0, offset: 0, data: [1, 2, 3], fin: true))
        #expect(throws: StreamError.self) {
            try stream.receive(frame(id: 0, offset: 0, data: [1, 2], fin: true))
        }

        var sendOnly = ReceiveStreamCore(
            id: 2,
            isLocallyInitiated: true,
            initialRecvMaxData: 4,
            maxBufferSize: 4
        )
        #expect(throws: StreamError.self) {
            try sendOnly.receive(frame(id: 2, offset: 0, data: [1], fin: false))
        }
    }

    @Test("partial receive reset exposes only its reliable prefix")
    func receiveStreamPartialReset() throws {
        var stream = ReceiveStreamCore(
            id: 0,
            isLocallyInitiated: true,
            initialRecvMaxData: 10,
            maxBufferSize: 10
        )
        try stream.receive(frame(id: 0, offset: 0, data: [1, 2, 3, 4, 5], fin: false))
        try stream.handleResetStreamAt(errorCode: 77, finalSize: 5, reliableSize: 3)

        #expect(stream.peek() == [1, 2, 3])
        #expect(stream.read() == [1, 2, 3])
        #expect(stream.recvState == .resetRead)
        #expect(stream.read() == nil)
    }

    @Test("flow controller updates connection stream and concurrency credit")
    func flowControlLifecycle() {
        var flow = FlowControllerCore(
            isClient: true,
            initialMaxData: 10,
            initialMaxStreamDataBidiLocal: 8,
            initialMaxStreamDataBidiRemote: 6,
            initialMaxStreamDataUni: 4,
            initialMaxStreamsBidi: 2,
            initialMaxStreamsUni: 1,
            peerMaxData: 4,
            peerMaxStreamsBidi: 1,
            peerMaxStreamsUni: 0
        )

        #expect(flow.canSend(bytes: 4))
        flow.recordBytesSent(4)
        #expect(flow.connectionSendWindow == 0)
        #expect(flow.generateDataBlocked()?.dataLimit == 4)
        flow.updateConnectionSendLimit(8)
        #expect(flow.connectionSendWindow == 4)
        #expect(flow.generateDataBlocked() == nil)

        flow.recordBytesReceived(6)
        #expect(flow.generateMaxData()?.maxData == 20)

        flow.initializeStream(0)
        #expect(flow.canReceiveOnStream(0, endOffset: 8))
        #expect(!flow.canReceiveOnStream(0, endOffset: 9))
        #expect(flow.recordStreamBytesReceived(0, endOffset: 7) == 7)
        #expect(flow.recordStreamBytesReceived(0, endOffset: 5) == 0)
        #expect(flow.generateMaxStreamData(for: 0)?.maxStreamData == 16)

        #expect(flow.canOpenStream(bidirectional: true))
        flow.recordLocalStreamOpened(bidirectional: true)
        #expect(!flow.canOpenStream(bidirectional: true))
        #expect(flow.generateStreamsBlocked(bidirectional: true)?.streamLimit == 1)

        flow.recordRemoteStreamOpened(bidirectional: true)
        #expect(flow.generateMaxStreams(bidirectional: true)?.maxStreams == 12)
    }

    private func frame(
        id: UInt64,
        offset: UInt64,
        data: [UInt8],
        fin: Bool
    ) -> StreamFrame {
        StreamFrame(
            streamID: id,
            offset: offset,
            data: data,
            fin: fin,
            hasLength: true
        )
    }
}
