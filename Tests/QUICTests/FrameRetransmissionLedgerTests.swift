import Foundation
import Testing
@testable import QUICConnection
@testable import QUICCore
@testable import QUICRecovery

@Suite("RFC 9002 frame retransmission ledger")
struct FrameRetransmissionLedgerTests {
    @Test("lost STREAM and RESET_STREAM_AT information is requeued")
    func lostReliableInformationIsRequeued() throws {
        let handler = try makeHandler()
        let now = ContinuousClock.Instant.now
        let stream = StreamFrame(
            streamID: 0,
            offset: 0,
            data: [0x01, 0x02, 0x03],
            fin: false,
            hasLength: true
        )
        let reset = ResetStreamAtFrame(
            streamID: 0,
            applicationErrorCode: 7,
            finalSize: 5,
            reliableSize: 3
        )

        record(
            handler: handler,
            packetNumber: 0,
            frames: [.stream(stream)],
            now: now
        )
        record(
            handler: handler,
            packetNumber: 1,
            frames: [.resetStreamAt(reset)],
            now: now
        )
        record(handler: handler, packetNumber: 2, frames: [.ping], now: now)
        record(handler: handler, packetNumber: 3, frames: [.ping], now: now)
        record(
            handler: handler,
            packetNumber: 4,
            frames: [.ack(AckFrame(largestAcknowledged: 0, ackDelay: 0, ackRanges: []))],
            now: now,
            ackEliciting: false
        )

        let ack = AckFrame(
            largestAcknowledged: 4,
            ackDelay: 0,
            ackRanges: [AckRange(gap: 0, rangeLength: 0)]
        )
        _ = try handler.processFrames([.ack(ack)], level: .application)

        let retransmitted = handler.getOutboundPackets().flatMap(\.frames)
        #expect(retransmitted.contains(.stream(stream)))
        #expect(retransmitted.contains(.resetStreamAt(reset)))
    }

    @Test("DATAGRAM information is never requeued after loss")
    func datagramIsNotRequeued() throws {
        let handler = try makeHandler()
        let now = ContinuousClock.Instant.now
        let datagram = DatagramFrame(data: [0xaa, 0xbb], hasLength: true)

        record(
            handler: handler,
            packetNumber: 0,
            frames: [.datagram(datagram)],
            now: now
        )
        record(handler: handler, packetNumber: 1, frames: [.ping], now: now)
        record(handler: handler, packetNumber: 2, frames: [.ping], now: now)
        record(handler: handler, packetNumber: 3, frames: [.ping], now: now)
        record(
            handler: handler,
            packetNumber: 4,
            frames: [],
            now: now,
            ackEliciting: false
        )

        let ack = AckFrame(
            largestAcknowledged: 4,
            ackDelay: 0,
            ackRanges: [AckRange(gap: 0, rangeLength: 0)]
        )
        _ = try handler.processFrames([.ack(ack)], level: .application)

        let retransmitted = handler.getOutboundPackets().flatMap(\.frames)
        #expect(!retransmitted.contains(.datagram(datagram)))
    }

    private func makeHandler() throws -> QUICConnectionHandler {
        let sourceConnectionID = try #require(ConnectionID.random(length: 8))
        let destinationConnectionID = try #require(ConnectionID.random(length: 8))
        var parameters = TransportParameters()
        parameters.initialSourceConnectionID = sourceConnectionID
        return QUICConnectionHandler(
            role: .client,
            version: .v1,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID,
            transportParameters: parameters
        )
    }

    private func record(
        handler: QUICConnectionHandler,
        packetNumber: UInt64,
        frames: [Frame],
        now: ContinuousClock.Instant,
        ackEliciting: Bool = true
    ) {
        handler.recordSentPacket(
            SentPacket(
                packetNumber: packetNumber,
                encryptionLevel: .application,
                timeSent: now,
                ackEliciting: ackEliciting,
                inFlight: ackEliciting,
                sentBytes: 1200
            ),
            frames: frames
        )
    }
}
