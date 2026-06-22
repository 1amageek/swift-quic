/// 1-RTT Key Update Live Wiring Tests (RFC 9001 §6)
///
/// These tests exercise the live connection wiring of 1-RTT key update — the path that selects
/// the AEAD opener by the received Key Phase bit, commits a peer-initiated update only after a
/// successful AEAD open, and initiates a local update when AEAD usage limits demand it. They drive
/// `PacketProcessor` directly (two processors acting as peers) because that is where the wiring
/// lives, while the underlying key-phase managers have their own crypto-layer unit tests.

import Testing
import Foundation
import Crypto
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto

@Suite("RFC 9001 §6 - 1-RTT Key Update Live Wiring")
struct KeyUpdateWiringTests {

    /// Distinct deterministic 32-byte application secrets shared by both peers so their key
    /// schedules derive matching key generations (client sealer ↔ server opener and vice versa).
    private static let clientSecret = SymmetricKey(data: Data(repeating: 0x3A, count: 32))
    private static let serverSecret = SymmetricKey(data: Data(repeating: 0x5C, count: 32))

    /// Builds a client/server pair of PacketProcessors with application (1-RTT) keys installed
    /// for the given cipher suite. Both share identical traffic secrets, so packets sealed by one
    /// can be opened by the other.
    private func makePeers(
        cipherSuite: QUICCipherSuite,
        dcidLength: Int = 8
    ) throws -> (client: PacketProcessor, server: PacketProcessor) {
        let info = KeysAvailableInfo(
            level: .application,
            clientSecret: Self.clientSecret,
            serverSecret: Self.serverSecret,
            cipherSuite: cipherSuite
        )
        let client = PacketProcessor(dcidLength: dcidLength)
        let server = PacketProcessor(dcidLength: dcidLength)
        try client.installKeys(info, isClient: true)
        try server.installKeys(info, isClient: false)
        return (client, server)
    }

    /// A non-empty, decodable 1-RTT payload large enough for the 16-byte header-protection sample
    /// (RFC 9001 §5.4.2 requires PN offset + 4 + 16 bytes of packet). A PING plus PADDING bytes
    /// (encoded as PADDING frames, byte 0x00) comfortably clears the minimum.
    private func pingFrames() -> [Frame] {
        [.ping, .padding(count: 30)]
    }

    private func shortHeader(dcid: ConnectionID) -> ShortHeader {
        ShortHeader(destinationConnectionID: dcid, packetNumberLength: 2)
    }

    // MARK: - Peer-initiated key update keeps decrypting

    @Test("Peer-initiated key update (phase flip) keeps the connection decrypting")
    func peerInitiatedKeyUpdateKeepsDecrypting() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let (client, server) = try makePeers(cipherSuite: .aes128GcmSha256)

        // Baseline: both start at phase 0.
        #expect(client.currentApplicationKeyPhase == 0)
        #expect(server.currentApplicationKeyPhase == 0)

        // Client sends a phase-0 packet; server decrypts it normally.
        let p0 = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 0)
        let parsed0 = try server.decryptPacket(p0)
        #expect(parsed0.keyPhase == 0)
        #expect(server.currentApplicationKeyPhase == 0, "Server must not rotate on a same-phase packet")

        // Client initiates a key update and sends a phase-1 packet.
        let newPhase = try client.initiateApplicationKeyUpdate()
        #expect(newPhase == 1)
        #expect(client.currentApplicationKeyPhase == 1)

        let p1 = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 1)

        // Server observes the flipped phase bit, derives the next opener, opens successfully, and
        // commits the update so its send phase now matches.
        let parsed1 = try server.decryptPacket(p1)
        #expect(parsed1.keyPhase == 1)
        #expect(server.currentApplicationKeyPhase == 1, "Server must commit the peer-initiated update")

        // Subsequent phase-1 packets continue to decrypt under the committed keys.
        let p2 = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 2)
        let parsed2 = try server.decryptPacket(p2)
        #expect(parsed2.keyPhase == 1)
        #expect(!parsed2.frames.isEmpty)
    }

    @Test("Reordered previous-phase packet still decrypts after a peer update")
    func reorderedPreviousPhasePacketStillDecrypts() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let (client, server) = try makePeers(cipherSuite: .aes128GcmSha256)

        // Pre-seal a phase-0 packet that will arrive AFTER the update (reordering).
        let oldPhasePacket = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 0)

        // Client updates and the server commits the update via a phase-1 packet.
        _ = try client.initiateApplicationKeyUpdate()
        let newPhasePacket = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 1)
        _ = try server.decryptPacket(newPhasePacket)
        #expect(server.currentApplicationKeyPhase == 1)

        // The reordered phase-0 packet must still open using the retained previous keys, and must
        // NOT roll the committed phase back to 0.
        let parsedOld = try server.decryptPacket(oldPhasePacket)
        #expect(parsedOld.keyPhase == 0)
        #expect(server.currentApplicationKeyPhase == 1,
                "A reordered old-phase packet must not revert the committed key phase")
    }

    // MARK: - Local-initiated key update at the usage limit

    @Test("Local key update at the AEAD usage limit rotates and the peer still decrypts")
    func localKeyUpdateAtUsageLimitRotates() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let (client, server) = try makePeers(cipherSuite: .aes128GcmSha256)

        // Drive the AEAD confidentiality counter past the approach threshold so that the wiring's
        // usage-based decision (PacketProcessor.shouldInitiateApplicationKeyUpdate) fires. We force
        // the manager to the threshold by recording encryptions directly via sealing many packets
        // would be too slow, so instead use the public knob the wiring exposes.
        #expect(client.currentApplicationKeyPhase == 0)

        // Sanity: with fresh keys, no update is yet demanded.
        #expect(client.shouldInitiateApplicationKeyUpdate == false)

        // Push usage to the AES-GCM confidentiality approach threshold (3/4 of 2^23).
        client.forceApplicationAEADUsageForTesting(packetsEncrypted: (1 << 23) * 3 / 4)
        #expect(client.shouldInitiateApplicationKeyUpdate == true,
                "Reaching the confidentiality approach threshold must demand a key update")

        // The send path initiates the update lazily; emulate generateOutboundPackets's check.
        if client.shouldInitiateApplicationKeyUpdate {
            _ = try client.initiateApplicationKeyUpdate()
        }
        #expect(client.currentApplicationKeyPhase == 1, "Local update must toggle the send phase")

        // After rotating, the usage counter resets, so no further update is immediately demanded.
        #expect(client.shouldInitiateApplicationKeyUpdate == false)

        // The peer can still decrypt packets sealed with the rotated keys.
        let packet = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 100)
        let parsed = try server.decryptPacket(packet)
        #expect(parsed.keyPhase == 1)
        #expect(server.currentApplicationKeyPhase == 1, "Peer commits the local-initiated update")
        #expect(!parsed.frames.isEmpty)
    }

    // MARK: - ChaCha20-Poly1305 coverage

    @Test("Key update works under TLS_CHACHA20_POLY1305_SHA256")
    func keyUpdateUnderChaCha20() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let (client, server) = try makePeers(cipherSuite: .chacha20Poly1305Sha256)

        // Phase 0 round-trip under ChaCha20-Poly1305.
        let p0 = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 0)
        let parsed0 = try server.decryptPacket(p0)
        #expect(parsed0.keyPhase == 0)

        // Peer-initiated update under ChaCha20-Poly1305 must derive ChaCha20 keys (not AES) on both
        // sides; a hardcoded AES opener would fail to open here.
        _ = try client.initiateApplicationKeyUpdate()
        let p1 = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 1)
        let parsed1 = try server.decryptPacket(p1)
        #expect(parsed1.keyPhase == 1)
        #expect(server.currentApplicationKeyPhase == 1)
        #expect(!parsed1.frames.isEmpty)

        // Further phase-1 packets continue to decrypt under the committed ChaCha20 keys.
        let p2 = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 2)
        let parsed2 = try server.decryptPacket(p2)
        #expect(parsed2.keyPhase == 1)
        #expect(!parsed2.frames.isEmpty)
    }

    // MARK: - Forged packet must not commit a key update

    @Test("Forged packet with a flipped phase bit that fails AEAD does NOT commit a key update")
    func forgedFlippedPhasePacketDoesNotCommitUpdate() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let (client, server) = try makePeers(cipherSuite: .aes128GcmSha256)

        // Establish a clean phase-0 baseline that decrypts.
        let good = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 0)
        _ = try server.decryptPacket(good)
        #expect(server.currentApplicationKeyPhase == 0)

        // Seal a legitimate phase-1 packet using the client's UPDATED keys to obtain a ciphertext
        // that carries a flipped (phase-1) bit, then corrupt it so the AEAD tag fails. Against a
        // server still at phase 0, header protection still removes cleanly (the HP key is unchanged
        // across phases), exposing the flipped phase bit, but the AEAD open MUST fail — so the
        // server MUST NOT commit a key update.
        _ = try client.initiateApplicationKeyUpdate()
        var forged = try client.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 1)
        let lastIndex = forged.index(before: forged.endIndex)
        forged[lastIndex] ^= 0xFF  // Corrupt the AEAD tag.

        #expect(throws: (any Error).self) {
            _ = try server.decryptPacket(forged)
        }

        // RFC 9001 §6.3: never update keys on a packet that cannot be authenticated. The committed
        // key phase MUST remain 0.
        #expect(server.currentApplicationKeyPhase == 0,
                "A forged phase-flipped packet that fails AEAD must not commit a key update")

        // A subsequent genuine phase-0 packet must still decrypt, proving the keys are intact. The
        // original `client` has rotated to phase 1, so use a fresh phase-0 client (same secrets) to
        // represent the legitimate peer that never updated.
        let (freshClient, _) = try makePeers(cipherSuite: .aes128GcmSha256)
        let genuinePhase0 = try freshClient.encryptShortHeaderPacket(
            frames: pingFrames(), header: shortHeader(dcid: dcid), packetNumber: 2)
        let parsed = try server.decryptPacket(genuinePhase0)
        #expect(parsed.keyPhase == 0)
        #expect(server.currentApplicationKeyPhase == 0)
    }
}
