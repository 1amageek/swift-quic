/// RFC 9221 - Unreliable Datagram Extension Tests
///
/// Verifies the connection-level DATAGRAM API:
/// - sendDatagram / incomingDatagrams round-trip a datagram over a full TLS handshake.
/// - sendDatagram throws when the peer did not advertise DATAGRAM support.
/// - sendDatagram throws when the datagram exceeds the negotiated max frame size.
/// - An oversized incoming DATAGRAM frame is rejected per RFC 9221 §5.

import Testing
import Foundation
import Synchronization
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICConnection

@Suite("RFC 9221 - Unreliable Datagram Extension", .timeLimit(.minutes(1)))
struct DatagramRFCTests {

    private static let serverSigningKey = SigningKey.generateP256()
    private static let serverCertificateChain = [Data([0x30, 0x82, 0x01, 0x00])]

    /// Creates a client connection. When `maxDatagramFrameSize > 0` the DATAGRAM extension
    /// is advertised; otherwise it stays disabled.
    private func createClient(
        dcid: ConnectionID,
        scid: ConnectionID,
        maxDatagramFrameSize: UInt64
    ) -> ManagedConnection {
        var config = QUICConfiguration()
        config.maxDatagramFrameSize = maxDatagramFrameSize
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        var tlsConfig = TLSConfiguration.client(serverName: "localhost", alpnProtocols: ["h3"])
        tlsConfig.expectedPeerPublicKey = Self.serverSigningKey.publicKeyBytes
        let tlsProvider = TLS13Handler(configuration: tlsConfig)

        return ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: SocketAddress(ipAddress: "127.0.0.1", port: 4433)
        )
    }

    private func createServer(
        dcid: ConnectionID,
        scid: ConnectionID,
        originalDCID: ConnectionID,
        maxDatagramFrameSize: UInt64
    ) -> ManagedConnection {
        var config = QUICConfiguration()
        config.maxDatagramFrameSize = maxDatagramFrameSize
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        var tlsConfig = TLSConfiguration()
        tlsConfig.alpnProtocols = ["h3"]
        tlsConfig.signingKey = Self.serverSigningKey
        tlsConfig.certificateChain = Self.serverCertificateChain
        let tlsProvider = TLS13Handler(configuration: tlsConfig)

        return ManagedConnection(
            role: .server,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            originalConnectionID: originalDCID,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: SocketAddress(ipAddress: "127.0.0.1", port: 54321)
        )
    }

    /// Drives a full client/server handshake to completion.
    private func completeHandshake(
        client: ManagedConnection,
        server: ManagedConnection
    ) async throws {
        let clientInitial = try await client.start()
        _ = try await server.start()
        var serverResponse: [Data] = []
        for packet in clientInitial {
            serverResponse.append(contentsOf: try await server.processDatagram(packet))
        }
        var clientResponse: [Data] = []
        for packet in serverResponse {
            clientResponse.append(contentsOf: try await client.processDatagram(packet))
        }
        for packet in clientResponse {
            let isLongHeader = (packet[0] & 0x80) != 0
            do {
                _ = try await server.processDatagram(packet)
            } catch {
                if server.handshakeState == .established && isLongHeader { continue }
                throw error
            }
        }
        #expect(client.isEstablished)
        #expect(server.isEstablished)
    }

    // MARK: - Round-trip

    @Test("sendDatagram / incomingDatagrams round-trip a datagram")
    func roundTrip() async throws {
        let clientSCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!
        let originalDCID = ConnectionID.random(length: 8)!

        let client = createClient(dcid: originalDCID, scid: clientSCID, maxDatagramFrameSize: 65535)
        let server = createServer(
            dcid: clientSCID, scid: serverSCID, originalDCID: originalDCID,
            maxDatagramFrameSize: 65535
        )
        try await completeHandshake(client: client, server: server)

        // Client sends a datagram; deliver the resulting packets to the server and read it
        // back from the server's incomingDatagrams stream.
        let payload = Data("unreliable hello".utf8)
        try await client.sendDatagram(payload)

        let packets = try client.generateOutboundPackets()
        #expect(!packets.isEmpty)

        var iterator = server.incomingDatagrams.makeAsyncIterator()
        for packet in packets {
            _ = try await server.processDatagram(packet)
        }

        let received = await iterator.next()
        #expect(received == payload)

        client.shutdown()
        server.shutdown()
    }

    // MARK: - Errors

    @Test("sendDatagram throws when the peer did not advertise support")
    func sendThrowsWhenPeerUnsupported() async throws {
        let clientSCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!
        let originalDCID = ConnectionID.random(length: 8)!

        // Client supports datagrams, server does NOT advertise support.
        let client = createClient(dcid: originalDCID, scid: clientSCID, maxDatagramFrameSize: 65535)
        let server = createServer(
            dcid: clientSCID, scid: serverSCID, originalDCID: originalDCID,
            maxDatagramFrameSize: 0
        )
        try await completeHandshake(client: client, server: server)

        await #expect(throws: QUICDatagramError.datagramsNotSupported) {
            try await client.sendDatagram(Data("nope".utf8))
        }

        client.shutdown()
        server.shutdown()
    }

    @Test("sendDatagram throws when the datagram exceeds the negotiated size")
    func sendThrowsWhenTooLarge() async throws {
        let clientSCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!
        let originalDCID = ConnectionID.random(length: 8)!

        // Server advertises a small limit; client must respect it.
        let serverLimit: UInt64 = 64
        let client = createClient(dcid: originalDCID, scid: clientSCID, maxDatagramFrameSize: 65535)
        let server = createServer(
            dcid: clientSCID, scid: serverSCID, originalDCID: originalDCID,
            maxDatagramFrameSize: serverLimit
        )
        try await completeHandshake(client: client, server: server)

        // A payload that, with frame overhead, exceeds the 64-byte limit.
        let tooLarge = Data(repeating: 0xAB, count: 100)
        await #expect(throws: QUICDatagramError.self) {
            try await client.sendDatagram(tooLarge)
        }

        // A payload within the negotiated size succeeds.
        let small = Data(repeating: 0xCD, count: 10)
        try await client.sendDatagram(small)

        client.shutdown()
        server.shutdown()
    }

    @Test("maxDatagramPayloadSize reflects the negotiated limit")
    func maxPayloadSize() async throws {
        let clientSCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!
        let originalDCID = ConnectionID.random(length: 8)!

        let serverLimit: UInt64 = 1200
        let client = createClient(dcid: originalDCID, scid: clientSCID, maxDatagramFrameSize: 65535)
        let server = createServer(
            dcid: clientSCID, scid: serverSCID, originalDCID: originalDCID,
            maxDatagramFrameSize: serverLimit
        )
        try await completeHandshake(client: client, server: server)

        // Largest payload P with 1 (type) + varint_len(P) + P <= 1200. For P in [64, 1197]
        // the length varint is 2 bytes, so overhead is 3 and P = 1197.
        let maxPayload = client.maxDatagramPayloadSize
        #expect(maxPayload == 1197)
        // A payload exactly at the limit is accepted; one byte more is rejected.
        try await client.sendDatagram(Data(repeating: 0x01, count: maxPayload))
        await #expect(throws: QUICDatagramError.self) {
            try await client.sendDatagram(Data(repeating: 0x01, count: maxPayload + 1))
        }

        client.shutdown()
        server.shutdown()
    }
}

// MARK: - Oversized Incoming DATAGRAM Rejection (handler-level)

@Suite("RFC 9221 §5 - Oversized Incoming DATAGRAM Rejection")
struct DatagramIncomingRejectionTests {

    private func makeHandler(advertised: UInt64) throws -> QUICConnectionHandler {
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        var params = TransportParameters()
        params.initialSourceConnectionID = scid
        params.maxDatagramFrameSize = advertised
        return QUICConnectionHandler(
            role: .server,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params
        )
    }

    @Test("An incoming DATAGRAM within the advertised size is accepted")
    func acceptsWithinLimit() throws {
        let handler = try makeHandler(advertised: 1200)
        let frame = Frame.datagram(DatagramFrame(data: Data(repeating: 0x7, count: 100)))
        let result = try handler.processFrames([frame], level: .application)
        #expect(result.datagrams.count == 1)
        #expect(result.datagrams.first == Data(repeating: 0x7, count: 100))
    }

    @Test("An incoming DATAGRAM larger than advertised is a protocol violation")
    func rejectsOversized() throws {
        let handler = try makeHandler(advertised: 64)
        // 100-byte payload + frame overhead exceeds the 64-byte advertised limit.
        let frame = Frame.datagram(DatagramFrame(data: Data(repeating: 0x9, count: 100)))
        #expect(throws: QUICError.self) {
            _ = try handler.processFrames([frame], level: .application)
        }
    }

    @Test("Receiving a DATAGRAM when we advertised no support is a violation")
    func rejectsWhenUnsupported() throws {
        let handler = try makeHandler(advertised: 0)
        let frame = Frame.datagram(DatagramFrame(data: Data([0x1, 0x2, 0x3])))
        #expect(throws: QUICError.self) {
            _ = try handler.processFrames([frame], level: .application)
        }
    }
}
