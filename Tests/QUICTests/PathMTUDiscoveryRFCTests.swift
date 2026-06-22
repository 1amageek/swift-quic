/// RFC 8899 / RFC 9000 §14 - DPLPMTUD State Machine Tests
///
/// These tests verify the PathMTUDiscovery state machine:
/// - A successful probe raises the effective max packet size.
/// - A lost/unacked probe stops the raise (and the state machine never feeds CC — that
///   contract is enforced by QUICConnectionHandler, tested separately).
/// - The peer's max_udp_payload_size and the configured ceiling are both respected.
/// - When disabled, the PMTU stays at the 1200-byte base.

import Testing
import Foundation
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICConnection

@Suite("RFC 8899 / RFC 9000 §14 - DPLPMTUD")
struct PathMTUDiscoveryRFCTests {

    // MARK: - Base / Disabled

    @Test("Disabled discovery stays at the 1200-byte base")
    func disabledStaysAtBase() {
        let pmtu = PathMTUDiscovery(enabled: false, maxProbeSize: 1500)

        #expect(pmtu.phase == .disabled)
        #expect(pmtu.currentMaxPacketSize == PathMTUDiscovery.basePLPMTU)
        #expect(pmtu.currentMaxPacketSize == 1200)
        #expect(pmtu.shouldProbe == false)
        #expect(pmtu.nextProbeSize() == nil)

        // Peer parameters never lift a disabled machine off the base.
        pmtu.setPeerMaxUDPPayloadSize(1500)
        #expect(pmtu.nextProbeSize() == nil)
        #expect(pmtu.currentMaxPacketSize == 1200)
    }

    @Test("Enabled discovery starts at the base and wants to probe")
    func enabledStartsAtBase() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)

        #expect(pmtu.phase == .base)
        #expect(pmtu.currentMaxPacketSize == 1200)
        #expect(pmtu.shouldProbe == true)
        let probe = pmtu.nextProbeSize()
        #expect(probe != nil)
        // First probe is the midpoint between base (1200) and ceiling (1500) = 1350.
        #expect(probe == 1350)
    }

    // MARK: - Successful probe raises the PMTU

    @Test("A successful probe raises the effective max packet size")
    func successfulProbeRaisesMTU() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)

        let target = try! #require(pmtu.nextProbeSize())
        pmtu.recordProbeSent(size: target, packetNumber: 10)
        #expect(pmtu.phase == .searching)
        #expect(pmtu.hasOutstandingProbe == true)

        let raised = pmtu.onProbeAcknowledged(packetNumber: 10)
        #expect(raised == true)
        #expect(pmtu.currentMaxPacketSize == target)
        #expect(pmtu.currentMaxPacketSize > 1200)
        #expect(pmtu.hasOutstandingProbe == false)
    }

    @Test("Repeated successful probes converge at the ceiling")
    func repeatedProbesConverge() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)

        var pn: UInt64 = 0
        // Drive probes until the search completes.
        while let target = pmtu.nextProbeSize() {
            pmtu.recordProbeSent(size: target, packetNumber: pn)
            #expect(pmtu.onProbeAcknowledged(packetNumber: pn))
            pn += 1
            if pn > 64 { break }  // Safety bound; binary search converges quickly.
        }

        #expect(pmtu.phase == .searchComplete)
        #expect(pmtu.currentMaxPacketSize == 1500)
        #expect(pmtu.shouldProbe == false)
    }

    // MARK: - Lost probe stops the raise

    @Test("A lost probe does not raise the PMTU and stops the search")
    func lostProbeStopsRaise() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)

        let target = try! #require(pmtu.nextProbeSize())
        pmtu.recordProbeSent(size: target, packetNumber: 7)

        let matched = pmtu.onProbeLost(packetNumber: 7)
        #expect(matched == true)
        // The PMTU is NOT raised by a lost probe.
        #expect(pmtu.currentMaxPacketSize == 1200)
        #expect(pmtu.hasOutstandingProbe == false)
    }

    @Test("Acknowledging a non-probe packet number is ignored")
    func nonProbeAckIgnored() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)
        let target = try! #require(pmtu.nextProbeSize())
        pmtu.recordProbeSent(size: target, packetNumber: 5)

        // A different packet number must not validate the outstanding probe.
        #expect(pmtu.onProbeAcknowledged(packetNumber: 999) == false)
        #expect(pmtu.currentMaxPacketSize == 1200)
        #expect(pmtu.hasOutstandingProbe == true)
    }

    @Test("Repeated base-size probe loss declares a black hole")
    func blackHoleDetection() {
        // With ceiling == base there is no room to probe, so force base-size probes by
        // recording probes at the base size directly and losing them MAX_PROBES times.
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 2000)

        for pn in 0..<UInt64(PathMTUDiscovery.maxProbes) {
            pmtu.recordProbeSent(size: PathMTUDiscovery.basePLPMTU, packetNumber: pn)
            #expect(pmtu.onProbeLost(packetNumber: pn))
        }

        #expect(pmtu.phase == .error)
        #expect(pmtu.currentMaxPacketSize == 1200)
    }

    // MARK: - Ceilings: peer max_udp_payload_size and configured probe size

    @Test("The configured probe ceiling is respected")
    func configuredCeilingRespected() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1400)
        #expect(pmtu.effectiveCeiling == 1400)

        var pn: UInt64 = 0
        while let target = pmtu.nextProbeSize() {
            #expect(target <= 1400)
            pmtu.recordProbeSent(size: target, packetNumber: pn)
            #expect(pmtu.onProbeAcknowledged(packetNumber: pn))
            pn += 1
            if pn > 64 { break }
        }
        // Never exceeds the configured ceiling.
        #expect(pmtu.currentMaxPacketSize <= 1400)
        #expect(pmtu.currentMaxPacketSize == 1400)
    }

    @Test("The peer's max_udp_payload_size caps the search ceiling")
    func peerMaxUDPPayloadCapsCeiling() {
        // Configured ceiling is high, but the peer only accepts up to 1350 bytes.
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)
        pmtu.setPeerMaxUDPPayloadSize(1350)

        #expect(pmtu.effectiveCeiling == 1350)

        var pn: UInt64 = 0
        while let target = pmtu.nextProbeSize() {
            #expect(target <= 1350)
            pmtu.recordProbeSent(size: target, packetNumber: pn)
            #expect(pmtu.onProbeAcknowledged(packetNumber: pn))
            pn += 1
            if pn > 64 { break }
        }
        // Discovery never raises beyond the peer's advertised limit (RFC 9000 §14).
        #expect(pmtu.currentMaxPacketSize <= 1350)
        #expect(pmtu.currentMaxPacketSize == 1350)
    }

    @Test("Peer limit below the base never lowers the PMTU below 1200")
    func peerLimitBelowBaseClamped() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)
        // A peer cannot advertise below the QUIC minimum 1200, but the machine must be
        // robust if it does: never drop below the base.
        pmtu.setPeerMaxUDPPayloadSize(800)
        #expect(pmtu.effectiveCeiling == 1200)
        #expect(pmtu.currentMaxPacketSize == 1200)
    }

    @Test("Reset returns the search to the base")
    func resetReturnsToBase() {
        let pmtu = PathMTUDiscovery(enabled: true, maxProbeSize: 1500)
        let target = try! #require(pmtu.nextProbeSize())
        pmtu.recordProbeSent(size: target, packetNumber: 1)
        #expect(pmtu.onProbeAcknowledged(packetNumber: 1))
        #expect(pmtu.currentMaxPacketSize > 1200)

        pmtu.reset()
        #expect(pmtu.phase == .base)
        #expect(pmtu.currentMaxPacketSize == 1200)
    }
}

// MARK: - Configuration

@Suite("DPLPMTUD Configuration")
struct PathMTUDiscoveryConfigTests {

    @Test("PMTU discovery is enabled by default with a 1500-byte ceiling")
    func defaults() {
        let config = QUICConfiguration()
        #expect(config.pmtuDiscoveryEnabled == true)
        #expect(config.pmtuMaxProbeSize == 1500)
    }

    @Test("PMTU discovery is configurable")
    func configurable() {
        var config = QUICConfiguration()
        config.pmtuDiscoveryEnabled = false
        config.pmtuMaxProbeSize = 9000
        #expect(config.pmtuDiscoveryEnabled == false)
        #expect(config.pmtuMaxProbeSize == 9000)
    }
}

// MARK: - Connection-level integration

@Suite("DPLPMTUD Connection Integration", .timeLimit(.minutes(1)))
struct PathMTUDiscoveryConnectionTests {

    private static let serverSigningKey = SigningKey.generateP256()
    private static let serverCertificateChain = [Data([0x30, 0x82, 0x01, 0x00])]

    private func createClient(
        dcid: ConnectionID,
        scid: ConnectionID,
        pmtuEnabled: Bool
    ) -> ManagedConnection {
        var config = QUICConfiguration()
        config.pmtuDiscoveryEnabled = pmtuEnabled
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
            remoteAddress: SocketAddress(ipAddress: "127.0.0.1", port: 4433),
            pmtuDiscoveryEnabled: config.pmtuDiscoveryEnabled,
            pmtuMaxProbeSize: config.pmtuMaxProbeSize
        )
    }

    private func createServer(
        dcid: ConnectionID,
        scid: ConnectionID,
        originalDCID: ConnectionID
    ) -> ManagedConnection {
        var config = QUICConfiguration()
        // Advertise a larger max_udp_payload_size so DPLPMTUD has headroom to probe above
        // the 1200-byte base (the default config advertises only 1200).
        config.maxUDPPayloadSize = 1500
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

    /// Drives a full client/server handshake to completion, returning client and server.
    private func handshake(
        pmtuEnabled: Bool
    ) async throws -> (client: ManagedConnection, server: ManagedConnection) {
        let clientSCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!
        let originalDCID = ConnectionID.random(length: 8)!

        let client = createClient(dcid: originalDCID, scid: clientSCID, pmtuEnabled: pmtuEnabled)
        let server = createServer(dcid: clientSCID, scid: serverSCID, originalDCID: originalDCID)

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
        return (client, server)
    }

    @Test("An acknowledged probe raises the connection's effective max packet size")
    func probeRaisesConnectionMTU() async throws {
        // Inline the handshake so we can fully pump packets both directions (the shared
        // handshake() helper discards the server's responses, which would swallow probe ACKs).
        let clientSCID = ConnectionID.random(length: 8)!
        let serverSCID = ConnectionID.random(length: 8)!
        let originalDCID = ConnectionID.random(length: 8)!

        let client = createClient(dcid: originalDCID, scid: clientSCID, pmtuEnabled: true)
        let server = createServer(dcid: clientSCID, scid: serverSCID, originalDCID: originalDCID)
        defer { client.shutdown(); server.shutdown() }

        // Drive the handshake, then keep pumping every packet both ways. Once the client is
        // established on a validated path it emits a DPLPMTUD probe; the server's ACK of that
        // probe flows back and raises the effective max packet size.
        var clientToServer = try await client.start()
        _ = try await server.start()

        var raised = false
        for _ in 0..<12 {
            // Deliver everything the client produced to the server, collect server output.
            var serverToClient: [Data] = []
            for packet in clientToServer {
                let isLongHeader = !packet.isEmpty && (packet[0] & 0x80) != 0
                do {
                    serverToClient.append(contentsOf: try await server.processDatagram(packet))
                } catch {
                    if server.handshakeState == .established && isLongHeader { continue }
                    throw error
                }
            }
            // Pull any packets the server queued on its own (probe ACKs, etc.).
            serverToClient.append(contentsOf: try server.generateOutboundPackets())

            // Deliver everything the server produced back to the client.
            var nextClientToServer: [Data] = []
            for packet in serverToClient {
                let isLongHeader = !packet.isEmpty && (packet[0] & 0x80) != 0
                do {
                    nextClientToServer.append(contentsOf: try await client.processDatagram(packet))
                } catch {
                    if client.handshakeState == .established && isLongHeader { continue }
                    throw error
                }
            }
            // Pull any packets the client queued on its own (the DPLPMTUD probe).
            nextClientToServer.append(contentsOf: try client.generateOutboundPackets())

            if client.currentMaxPacketSize > 1200 {
                raised = true
                break
            }
            clientToServer = nextClientToServer
            if clientToServer.isEmpty { break }
        }

        #expect(client.isEstablished)
        // The acknowledged probe raised the effective max packet size above the base.
        #expect(raised)
        #expect(client.currentMaxPacketSize > 1200)
    }

    @Test("Disabled discovery keeps the connection at 1200 and never probes")
    func disabledStaysAt1200() async throws {
        let (client, server) = try await handshake(pmtuEnabled: false)
        defer { client.shutdown(); server.shutdown() }

        #expect(client.pmtuPhase == .disabled)
        #expect(client.currentMaxPacketSize == 1200)

        // No probe is generated; no outbound packet exceeds the base.
        let packets = try client.generateOutboundPackets()
        for packet in packets {
            #expect(packet.count <= 1200)
        }
        #expect(client.currentMaxPacketSize == 1200)
    }
}
