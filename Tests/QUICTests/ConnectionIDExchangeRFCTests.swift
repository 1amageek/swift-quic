/// RFC 9000 §7.2 Connection ID Exchange Compliance Tests
///
/// These tests verify compliance with RFC 9000 Section 7.2:
/// - Client MUST update DCID to server's SCID from first Initial packet
/// - Subsequent packets (Handshake, 1-RTT) use the updated DCID
/// - Server uses client's SCID as DCID throughout the connection

import Testing
import Foundation
import Synchronization
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICConnection

@Suite("RFC 9000 §7.2 - Connection ID Exchange During Handshake")
struct ConnectionIDExchangeRFCTests {

    /// Shared server signing key for tests
    private static let serverSigningKey = SigningKey.generateP256()
    /// Mock certificate chain for server
    private static let serverCertificateChain = [Data([0x30, 0x82, 0x01, 0x00])]

    /// Creates a client ManagedConnection with TLS13Handler
    private func createClient(dcid: ConnectionID, scid: ConnectionID) -> ManagedConnection {
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        var tlsConfig = TLSConfiguration.client(serverName: "localhost", alpnProtocols: ["h3"])
        tlsConfig.expectedPeerPublicKey = Self.serverSigningKey.publicKeyBytes
        let tlsProvider = TLS13Handler(configuration: tlsConfig)

        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        return ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )
    }

    /// Creates a server ManagedConnection with TLS13Handler
    private func createServer(dcid: ConnectionID, scid: ConnectionID, originalDCID: ConnectionID) -> ManagedConnection {
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        var tlsConfig = TLSConfiguration()
        tlsConfig.alpnProtocols = ["h3"]
        tlsConfig.signingKey = Self.serverSigningKey
        tlsConfig.certificateChain = Self.serverCertificateChain
        let tlsProvider = TLS13Handler(configuration: tlsConfig)

        let address = SocketAddress(ipAddress: "127.0.0.1", port: 54321)

        return ManagedConnection(
            role: .server,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            originalConnectionID: originalDCID,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )
    }

    // MARK: - Client Updates DCID from Server Initial

    @Test("Client updates DCID to server's SCID from Initial packet")
    func clientUpdatesDCIDFromServerInitial() async throws {
        // RFC 9000 §7.2: A client MUST change the destination connection ID
        // it uses for sending packets to match the value from the Source
        // Connection ID field of the first Initial packet sent by the server.

        let clientSCID = ConnectionID.random(length: 8)!
        let initialClientDCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!

        // Create client with initial DCID
        let client = createClient(dcid: initialClientDCID, scid: clientSCID)

        // Verify client starts with initial DCID
        #expect(client.destinationConnectionID == initialClientDCID)

        // Create server
        let server = createServer(dcid: clientSCID, scid: serverSCID, originalDCID: initialClientDCID)

        // Client starts handshake
        let clientInitial = try await client.start()
        #expect(!clientInitial.isEmpty)

        // Server must also start to derive Initial keys
        _ = try await server.start()

        // Server processes client Initial and generates response
        var serverResponse: [Data] = []
        for packet in clientInitial {
            let response = try await server.processDatagram(packet)
            serverResponse.append(contentsOf: response)
        }

        #expect(!serverResponse.isEmpty, "Server should send Initial response")

        // Client receives server Initial packet (contains serverSCID)
        for packet in serverResponse {
            _ = try await client.processDatagram(packet)
        }

        // Verify: Client should have updated DCID to server's SCID
        #expect(client.destinationConnectionID == serverSCID,
               "Client MUST update DCID to server's SCID after receiving Initial packet")
        #expect(client.destinationConnectionID != initialClientDCID,
               "Client should no longer use initial DCID")
    }

    @Test("Subsequent Handshake packets use updated DCID", .timeLimit(.minutes(1)))
    func handshakePacketsUseUpdatedDCID() async throws {
        // RFC 9000 §7.2: All subsequent packets MUST use the new DCID

        let clientSCID = ConnectionID.random(length: 8)!
        let initialClientDCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!

        let client = createClient(dcid: initialClientDCID, scid: clientSCID)
        let server = createServer(dcid: clientSCID, scid: serverSCID, originalDCID: initialClientDCID)

        // Client starts handshake
        let clientInitial = try await client.start()
        _ = try await server.start()

        // Server processes and responds
        var serverResponse: [Data] = []
        for packet in clientInitial {
            let response = try await server.processDatagram(packet)
            serverResponse.append(contentsOf: response)
        }

        // Client receives server Initial
        for packet in serverResponse {
            _ = try await client.processDatagram(packet)
        }

        // Client should have updated DCID
        #expect(client.destinationConnectionID == serverSCID)

        // Generate more outbound packets (should use updated DCID)
        let outboundPackets = try client.generateOutboundPackets()

        // Verify all packets in the outbound queue use updated DCID
        for packet in outboundPackets {
            let headerInfo = try extractHeaderInfoFromPacket(packet)
            #expect(headerInfo.dcid == serverSCID,
                   "All packets MUST use updated DCID")
        }
    }

    // MARK: - Helper Functions

    /// Extracts header info from an encrypted packet
    private func extractHeaderInfoFromPacket(_ packet: Data) throws -> (dcid: ConnectionID, scid: ConnectionID?) {
        let processor = PacketProcessor(dcidLength: 8)
        let headerInfo = try processor.extractHeaderInfo(from: packet)
        return (dcid: headerInfo.dcid, scid: headerInfo.scid)
    }
}

/// RFC 9000 §19.15 — NEW_CONNECTION_ID retirement loop must be bounded by the set of
/// connection IDs we actually hold, never by the peer-supplied `retire_prior_to` value.
@Suite("RFC 9000 §19.15 - NEW_CONNECTION_ID retirement bound")
struct NewConnectionIDRetirementBoundTests {

    @Test("Retirement loop is bounded by held CIDs, not retire_prior_to", .timeLimit(.minutes(1)))
    func retirementBoundedByHeldCIDs() throws {
        // A frame whose retire_prior_to equals its sequence number is structurally valid,
        // but the sequence number can be large on a long-lived connection. Processing such a
        // frame must do work proportional to the CIDs we store, not to the numeric range
        // [0, retire_prior_to). A huge retire_prior_to must not drive a multi-billion-iteration
        // loop; this test would hang under the old `for seq in 0..<retire_prior_to` behavior.
        let manager = ConnectionIDManager(activeConnectionIDLimit: 8)

        // Store a single peer CID at a low sequence number.
        let cid0 = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        try manager.handleNewConnectionID(
            NewConnectionIDFrame(
                sequenceNumber: 0,
                retirePriorTo: 0,
                connectionID: cid0,
                statelessResetToken: Data(repeating: 0xAA, count: 16)
            )
        )

        // A new CID with a very large sequence number and an equally large retire_prior_to.
        let bigSeq: UInt64 = 1_000_000_000  // would loop a billion times if unbounded
        let cidBig = try ConnectionID(bytes: Data([0x05, 0x06, 0x07, 0x08]))
        try manager.handleNewConnectionID(
            NewConnectionIDFrame(
                sequenceNumber: bigSeq,
                retirePriorTo: bigSeq,  // valid (== sequence number); retires everything below
                connectionID: cidBig,
                statelessResetToken: Data(repeating: 0xBB, count: 16)
            )
        )

        // The low-sequence CID must have been retired, the new one retained.
        let available = manager.availablePeerCIDs
        #expect(available.count == 1)
        #expect(available.first?.sequenceNumber == bigSeq)
    }

    @Test("Hostile retire_prior_to > sequence_number is rejected before any retirement")
    func hostileRetirePriorToRejected() throws {
        // The validating frame initializer must reject the out-of-range value, so the
        // manager never even sees it. Constructing the frame throws.
        let cid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        #expect(throws: FrameError.self) {
            _ = try NewConnectionIDFrame(
                sequenceNumber: 1,
                retirePriorTo: (1 << 62) - 1,
                connectionID: cid,
                statelessResetToken: Data(repeating: 0x00, count: 16)
            )
        }
    }
}
