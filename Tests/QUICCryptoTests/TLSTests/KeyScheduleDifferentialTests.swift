import Testing
import Foundation
import Crypto
@testable import QUICCrypto
import QUICTLSCore
import P2PCrypto

/// Byte-for-byte differential tests for the Embedded-clean TLS 1.3 key schedule
/// (`TLSKeyScheduleCore<C>` / `TLSExpandLabel<C>` / `TLSTranscriptHashCore<C>`)
/// against a direct swift-crypto reference implementation.
///
/// This is the correctness oracle for the crypto-seam extraction: it proves the new
/// generic `<C: CryptoProvider>` path, specialised at `C = QUICCryptoProvider`,
/// produces bit-identical secrets/labels/transcripts to the historical
/// swift-crypto (`HKDF`/`SHA256`/`SHA384`/`HMAC`) computation it replaced.
@Suite("TLS Key Schedule Differential")
struct KeyScheduleDifferentialTests {

    private typealias P = QUICCryptoProvider

    // MARK: - Reference helpers (direct swift-crypto, the pre-seam path)

    /// RFC 8446 §7.1 HkdfLabel construction, identical to the historical adapter.
    private func referenceHkdfLabel(label: String, context: Data, length: Int) -> Data {
        let fullLabel = "tls13 " + label
        let labelBytes = Data(fullLabel.utf8)
        var hkdfLabel = Data(capacity: 4 + labelBytes.count + context.count)
        hkdfLabel.append(UInt8(length >> 8))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(labelBytes.count))
        hkdfLabel.append(labelBytes)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)
        return hkdfLabel
    }

    private func referenceExpandLabelSHA256(secret: Data, label: String, context: Data, length: Int) -> Data {
        let info = referenceHkdfLabel(label: label, context: context, length: length)
        let okm = HKDF<SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: secret), info: info, outputByteCount: length)
        return okm.withUnsafeBytes { Data($0) }
    }

    private func referenceExpandLabelSHA384(secret: Data, label: String, context: Data, length: Int) -> Data {
        let info = referenceHkdfLabel(label: label, context: context, length: length)
        let okm = HKDF<SHA384>.expand(
            pseudoRandomKey: SymmetricKey(data: secret), info: info, outputByteCount: length)
        return okm.withUnsafeBytes { Data($0) }
    }

    // MARK: - HkdfLabel bytes

    @Test("HkdfLabel bytes match RFC 8446 construction (empty + non-empty context)")
    func hkdfLabelBytesMatch() throws {
        let cases: [(String, Data, Int)] = [
            ("derived", Data(), 32),
            ("derived", Data(), 48),
            ("c hs traffic", Data(repeating: 0xAA, count: 32), 32),
            ("key", Data(), 16),
            ("iv", Data(), 12),
            ("resumption", Data([0x01, 0x02, 0x03]), 32),
        ]
        for (label, context, length) in cases {
            let core = TLSExpandLabel<P>.hkdfLabelBytes(label: label, context: [UInt8](context), length: length)
            let reference = referenceHkdfLabel(label: label, context: context, length: length)
            #expect(Data(core) == reference, "HkdfLabel mismatch for \(label)/\(length)")
        }
    }

    // MARK: - HKDF-Expand-Label (SHA-256 and SHA-384)

    @Test("HKDF-Expand-Label is byte-identical to swift-crypto (SHA-256)")
    func expandLabelSHA256Matches() throws {
        let secret = Data(repeating: 0x42, count: 32)
        let context = Data(repeating: 0xBB, count: 32)
        let core = try TLSExpandLabel<P>.expandLabel(
            secret: [UInt8](secret), label: "c hs traffic", context: [UInt8](context), length: 32, hash: .sha256)
        let reference = referenceExpandLabelSHA256(secret: secret, label: "c hs traffic", context: context, length: 32)
        #expect(Data(core) == reference)
    }

    @Test("HKDF-Expand-Label is byte-identical to swift-crypto (SHA-384)")
    func expandLabelSHA384Matches() throws {
        let secret = Data(repeating: 0x42, count: 48)
        let context = Data(repeating: 0xCC, count: 48)
        let core = try TLSExpandLabel<P>.expandLabel(
            secret: [UInt8](secret), label: "s hs traffic", context: [UInt8](context), length: 48, hash: .sha384)
        let reference = referenceExpandLabelSHA384(secret: secret, label: "s hs traffic", context: context, length: 48)
        #expect(Data(core) == reference)
    }

    // MARK: - Empty transcript hash

    @Test("Empty transcript hash matches SHA-256/384 of empty input")
    func emptyTranscriptHashMatches() throws {
        #expect(Data(TLSExpandLabel<P>.emptyTranscriptHash(hash: .sha256)) == Data(SHA256.hash(data: Data())))
        #expect(Data(TLSExpandLabel<P>.emptyTranscriptHash(hash: .sha384)) == Data(SHA384.hash(data: Data())))
    }

    // MARK: - Full handshake/application secret derivation

    @Test("Handshake + application secrets match a direct swift-crypto schedule (SHA-256)")
    func fullScheduleSHA256Matches() throws {
        let sharedSecret = Data(repeating: 0x11, count: 32)
        let hsTranscript = Data(repeating: 0xAA, count: 32)
        let appTranscript = Data(repeating: 0xBB, count: 32)

        // Core (seam) path.
        var core = TLSKeyScheduleCore<P>(cipherSuite: .aes128GCMSHA256)
        let (coreClientHS, coreServerHS) = try core.deriveHandshakeSecrets(
            sharedSecret: [UInt8](sharedSecret), transcriptHash: [UInt8](hsTranscript))
        let (coreClientApp, coreServerApp) = try core.deriveApplicationSecrets(
            transcriptHash: [UInt8](appTranscript))

        // Reference path (direct swift-crypto, mirroring RFC 8446 §7.1).
        let zeros = Data(repeating: 0, count: 32)
        let earlySecret = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: zeros), salt: zeros)
        let emptyHash = Data(SHA256.hash(data: Data()))
        let derivedForHS = referenceExpandLabelSHA256(
            secret: Data(earlySecret.withUnsafeBytes { Data($0) }), label: "derived", context: emptyHash, length: 32)
        let handshakeSecret = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: sharedSecret), salt: derivedForHS)
        let hsData = handshakeSecret.withUnsafeBytes { Data($0) }
        let refClientHS = referenceExpandLabelSHA256(secret: hsData, label: "c hs traffic", context: hsTranscript, length: 32)
        let refServerHS = referenceExpandLabelSHA256(secret: hsData, label: "s hs traffic", context: hsTranscript, length: 32)

        let derivedForMaster = referenceExpandLabelSHA256(secret: hsData, label: "derived", context: emptyHash, length: 32)
        let masterSecret = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: zeros), salt: derivedForMaster)
        let msData = masterSecret.withUnsafeBytes { Data($0) }
        let refClientApp = referenceExpandLabelSHA256(secret: msData, label: "c ap traffic", context: appTranscript, length: 32)
        let refServerApp = referenceExpandLabelSHA256(secret: msData, label: "s ap traffic", context: appTranscript, length: 32)

        #expect(Data(coreClientHS) == refClientHS)
        #expect(Data(coreServerHS) == refServerHS)
        #expect(Data(coreClientApp) == refClientApp)
        #expect(Data(coreServerApp) == refServerApp)
    }

    // MARK: - Finished verify_data

    @Test("Finished verify_data matches HMAC over the finished key (SHA-256 + SHA-384)")
    func finishedVerifyDataMatches() throws {
        let baseSecret256 = Data(repeating: 0x42, count: 32)
        let transcript256 = Data(repeating: 0xBB, count: 32)
        let core256 = TLSKeyScheduleCore<P>(cipherSuite: .aes128GCMSHA256)
        let coreFinishedKey256 = try core256.finishedKey(from: [UInt8](baseSecret256))
        let coreVerify256 = core256.finishedVerifyData(forKey: coreFinishedKey256, transcriptHash: [UInt8](transcript256))

        let refFinishedKey256 = referenceExpandLabelSHA256(secret: baseSecret256, label: "finished", context: Data(), length: 32)
        let refVerify256 = Data(HMAC<SHA256>.authenticationCode(
            for: transcript256, using: SymmetricKey(data: refFinishedKey256)))
        #expect(Data(coreVerify256) == refVerify256)

        let baseSecret384 = Data(repeating: 0x42, count: 48)
        let transcript384 = Data(repeating: 0xCC, count: 48)
        let core384 = TLSKeyScheduleCore<P>(cipherSuite: .aes256GCMSHA384)
        let coreFinishedKey384 = try core384.finishedKey(from: [UInt8](baseSecret384))
        let coreVerify384 = core384.finishedVerifyData(forKey: coreFinishedKey384, transcriptHash: [UInt8](transcript384))

        let refFinishedKey384 = referenceExpandLabelSHA384(secret: baseSecret384, label: "finished", context: Data(), length: 48)
        let refVerify384 = Data(HMAC<SHA384>.authenticationCode(
            for: transcript384, using: SymmetricKey(data: refFinishedKey384)))
        #expect(Data(coreVerify384) == refVerify384)
    }

    // MARK: - Transcript hash

    @Test("Transcript hash matches running SHA-256/384 over concatenated messages")
    func transcriptHashMatches() throws {
        let messages = [
            Data([0x01, 0x02, 0x03]),
            Data([0x04, 0x05, 0x06, 0x07]),
            Data(repeating: 0x55, count: 64),
        ]

        var core256 = TLSTranscriptHashCore<P>(hash: .sha256)
        var core384 = TLSTranscriptHashCore<P>(hash: .sha384)
        var concatenated = Data()
        for message in messages {
            core256.update(with: [UInt8](message))
            core384.update(with: [UInt8](message))
            concatenated.append(message)
        }
        #expect(Data(core256.currentHash()) == Data(SHA256.hash(data: concatenated)))
        #expect(Data(core384.currentHash()) == Data(SHA384.hash(data: concatenated)))
        #expect(core256.messageCount == messages.count)
    }

    @Test("Transcript hash copy is independent of further updates")
    func transcriptHashCopyIndependent() throws {
        var core = TLSTranscriptHashCore<P>(hash: .sha256)
        core.update(with: [0x01, 0x02])
        let snapshot = core            // value-type copy
        let hashBefore = Data(snapshot.currentHash())
        core.update(with: [0x03, 0x04])
        // The snapshot must not see the later update.
        #expect(Data(snapshot.currentHash()) == hashBefore)
        #expect(Data(core.currentHash()) != hashBefore)
    }

    // MARK: - Adapter parity (the path tests actually exercise)

    @Test("Adapter TLSKeySchedule routes byte-identically through the seam")
    func adapterParity() throws {
        let sharedSecret = Data(repeating: 0x11, count: 32)
        let transcript = Data(repeating: 0xAA, count: 32)

        var adapter = TLSKeySchedule()
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        // Build a SharedSecret whose raw bytes equal `sharedSecret` is not possible via
        // the public API; instead compare the adapter against the core for the same
        // raw shared-secret bytes by using deriveHandshakeSecrets on the core directly.
        var core = TLSKeyScheduleCore<P>(cipherSuite: .aes128GCMSHA256)
        let (coreClient, coreServer) = try core.deriveHandshakeSecrets(
            sharedSecret: [UInt8](sharedSecret), transcriptHash: [UInt8](transcript))

        // Drive the adapter through a real X25519 shared secret and confirm it equals a
        // core derivation fed the same raw bytes.
        let peer = Curve25519.KeyAgreement.PrivateKey().publicKey
        let realShared = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        let realSharedBytes = realShared.withUnsafeBytes { [UInt8]($0) }
        let (adapterClient, adapterServer) = try adapter.deriveHandshakeSecrets(
            sharedSecret: realShared, transcriptHash: transcript)
        var coreForReal = TLSKeyScheduleCore<P>(cipherSuite: .aes128GCMSHA256)
        let (coreRealClient, coreRealServer) = try coreForReal.deriveHandshakeSecrets(
            sharedSecret: realSharedBytes, transcriptHash: [UInt8](transcript))

        #expect(adapterClient.withUnsafeBytes { Data($0) } == Data(coreRealClient))
        #expect(adapterServer.withUnsafeBytes { Data($0) } == Data(coreRealServer))
        // Sanity: the fixed-bytes core derivation is self-consistent.
        #expect(Data(coreClient).count == 32)
        #expect(Data(coreServer).count == 32)
    }
}
