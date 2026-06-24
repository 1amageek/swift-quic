import Testing
import Foundation
import Crypto
@testable import QUICCore
@testable import QUICCrypto
import QUICPacketProtectionCore
import P2PCrypto
import P2PCoreBytes

/// Byte-for-byte differential tests for the Embedded-clean packet-protection core
/// (`SuiteProtector<C>` / `PacketProtector<C, A>`) against RFC 9001 Appendix A
/// expected bytes AND against the legacy concrete `AES128GCMOpener`/`Sealer` API.
///
/// This is the correctness oracle for the existential→generic + crypto-seam
/// refactor: it proves the new generic path produces exactly the RFC vectors and
/// is bit-identical to the historical opener/sealer surface.
@Suite("RFC 9001 Appendix A - SuiteProtector Differential")
struct PacketProtectionDifferentialTests {

    // RFC 9001 Appendix A.2 client Initial key material (DCID 0x8394c8f03e515708).
    static let clientKey: [UInt8] = [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    ]
    static let clientIV: [UInt8] = [
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    ]
    static let clientHP: [UInt8] = [
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    ]
    // RFC 9001 A.2: the 16-byte header-protection sample from the protected packet.
    static let clientSample: [UInt8] = [
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
    ]
    // RFC 9001 A.2: the header-protection mask = AES-ECB(hp, sample)[0..<5].
    static let expectedMask: [UInt8] = [0x43, 0x7b, 0x9a, 0xec, 0x36]

    private func makeClientProtector() throws -> SuiteProtector<QUICCryptoProvider> {
        try SuiteProtector<QUICCryptoProvider>.make(
            suite: .aes128GCM,
            key: Self.clientKey,
            iv: Self.clientIV,
            hpKey: Self.clientHP)
    }

    @Test("RFC 9001 A.2: SuiteProtector AES header-protection mask matches expected bytes")
    func aesHeaderProtectionMaskMatchesRFC() throws {
        let protector = try makeClientProtector()
        let mask = try protector.headerProtectionMask(sample: Self.clientSample)
        #expect(mask == Self.expectedMask)
    }

    @Test("RFC 9001 A.2: protected first byte 0xc3 -> 0xc0 via the generic path")
    func protectedFirstByteMatchesRFC() throws {
        let protector = try makeClientProtector()
        // RFC 9001 A.2 unprotected long-header first byte is 0xc3; PN length 4 bytes.
        let (firstByte, _) = try protector.applyHeaderProtection(
            sample: Self.clientSample,
            firstByte: 0xc3,
            packetNumberBytes: [0x00, 0x00, 0x00, 0x02])
        // Long header masks the low 4 bits: 0xc3 ^ (0x43 & 0x0f) = 0xc3 ^ 0x03 = 0xc0.
        #expect(firstByte == 0xc0)
    }

    @Test("Header protection is self-inverse (apply then remove restores input)")
    func headerProtectionRoundTrip() throws {
        let protector = try makeClientProtector()
        let firstByte: UInt8 = 0xc3
        let pn: [UInt8] = [0x00, 0x00, 0x00, 0x02]
        let (pFirst, pPN) = try protector.applyHeaderProtection(
            sample: Self.clientSample, firstByte: firstByte, packetNumberBytes: pn)
        let (uFirst, uPN) = try protector.removeHeaderProtection(
            sample: Self.clientSample, firstByte: pFirst, packetNumberBytes: pPN)
        #expect(uFirst == firstByte)
        #expect(uPN == pn)
    }

    @Test("AEAD seal/open round-trips through the generic SuiteProtector")
    func aeadRoundTrip() throws {
        let protector = try makeClientProtector()
        let plaintext: [UInt8] = Array("RFC 9001 packet protection".utf8)
        let header: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x01]
        let sealed = try protector.seal(plaintext, packetNumber: 2, header: header)
        #expect(sealed.count == plaintext.count + 16)  // ciphertext || 16-byte tag
        let opened = try protector.open(sealed, packetNumber: 2, header: header)
        #expect(opened == plaintext)
    }

    @Test("AEAD open MUST throw on tag mismatch (no silent fallback)")
    func aeadAuthFailureThrows() throws {
        let protector = try makeClientProtector()
        let plaintext: [UInt8] = Array("authenticated payload".utf8)
        let header: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x01]
        var sealed = try protector.seal(plaintext, packetNumber: 7, header: header)
        sealed[sealed.count - 1] ^= 0xFF  // corrupt the tag
        #expect(throws: PacketProtectionError.self) {
            _ = try protector.open(sealed, packetNumber: 7, header: header)
        }
    }

    @Test("AEAD open with wrong AAD MUST throw (header is authenticated)")
    func aeadWrongAADThrows() throws {
        let protector = try makeClientProtector()
        let plaintext: [UInt8] = Array("authenticated payload".utf8)
        let header: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x01]
        let sealed = try protector.seal(plaintext, packetNumber: 7, header: header)
        let wrongHeader: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x02]
        #expect(throws: PacketProtectionError.self) {
            _ = try protector.open(sealed, packetNumber: 7, header: wrongHeader)
        }
    }

    // MARK: - Differential against the legacy concrete opener/sealer API

    @Test("SuiteProtector is byte-identical to the legacy AES128GCMSealer path")
    func differentialAgainstLegacySealer() throws {
        let protector = try makeClientProtector()
        let keyMaterial = KeyMaterial(
            key: SymmetricKey(data: Data(Self.clientKey)),
            iv: Data(Self.clientIV),
            hp: SymmetricKey(data: Data(Self.clientHP)),
            cipherSuite: .aes128GcmSha256)
        let sealer = try AES128GCMSealer(keyMaterial: keyMaterial)

        let plaintext: [UInt8] = Array("differential equality check".utf8)
        let header: [UInt8] = [0xc3, 0x00, 0x00, 0x00, 0x01, 0x08]

        let coreCiphertext = try protector.seal(plaintext, packetNumber: 5, header: header)
        let legacyCiphertext = try sealer.seal(
            plaintext: Data(plaintext), packetNumber: 5, header: Data(header))
        #expect(coreCiphertext == [UInt8](legacyCiphertext))

        let (coreFB, corePN) = try protector.applyHeaderProtection(
            sample: Self.clientSample, firstByte: 0xc3, packetNumberBytes: [0x00, 0x00, 0x00, 0x05])
        let (legacyFB, legacyPN) = try sealer.applyHeaderProtection(
            sample: Data(Self.clientSample), firstByte: 0xc3,
            packetNumberBytes: Data([0x00, 0x00, 0x00, 0x05]))
        #expect(coreFB == legacyFB)
        #expect(corePN == [UInt8](legacyPN))
    }

    @Test("Legacy AES128GCMOpener decrypts a SuiteProtector-sealed packet (interop)")
    func differentialOpenerInterop() throws {
        let protector = try makeClientProtector()
        let keyMaterial = KeyMaterial(
            key: SymmetricKey(data: Data(Self.clientKey)),
            iv: Data(Self.clientIV),
            hp: SymmetricKey(data: Data(Self.clientHP)),
            cipherSuite: .aes128GcmSha256)
        let opener = try AES128GCMOpener(keyMaterial: keyMaterial)

        let plaintext: [UInt8] = Array("cross-path interop".utf8)
        let header: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x01]
        let sealed = try protector.seal(plaintext, packetNumber: 9, header: header)
        let opened = try opener.open(
            ciphertext: Data(sealed), packetNumber: 9, header: Data(header))
        #expect([UInt8](opened) == plaintext)
    }

    // MARK: - Core key derivation (QUICKeyDerivation over the seam)

    @Test("RFC 9001 A.2: QUICKeyDerivation derives client key/iv/hp byte-for-byte")
    func coreKeyDerivationMatchesRFC() throws {
        // RFC 9001 A.1 client DCID -> initial secret -> client_initial_secret.
        let dcid: [UInt8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        // RFC 9001 §5.2 v1 initial salt.
        let salt: [UInt8] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a,
        ]
        let (clientSecret, _) = try QUICKeyDerivation<QUICCryptoProvider>.initialSecrets(
            connectionID: dcid, salt: salt)
        let (key, iv, hpKey) = try QUICKeyDerivation<QUICCryptoProvider>.packetKeys(
            secret: clientSecret, suite: .aes128GCM)
        #expect(key == Self.clientKey)
        #expect(iv == Self.clientIV)
        #expect(hpKey == Self.clientHP)
    }

    @Test("QUICKeyDerivation.protector reproduces the RFC A.2 HP mask end-to-end")
    func coreProtectorFromConnectionIDMatchesRFC() throws {
        let dcid: [UInt8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        let salt: [UInt8] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a,
        ]
        let (clientSecret, _) = try QUICKeyDerivation<QUICCryptoProvider>.initialSecrets(
            connectionID: dcid, salt: salt)
        let protector = try QUICKeyDerivation<QUICCryptoProvider>.protector(
            secret: clientSecret, suite: .aes128GCM)
        let mask = try protector.headerProtectionMask(sample: Self.clientSample)
        #expect(mask == Self.expectedMask)
    }

    // MARK: - ChaCha20-Poly1305 suite (RFC 9001 A.5 HP mask)

    @Test("RFC 9001 A.5: ChaCha20 SuiteProtector header-protection mask matches expected bytes")
    func chaCha20HeaderProtectionMaskMatchesRFC() throws {
        // RFC 9001 A.5 short-header HP key + sample.
        let hpKey: [UInt8] = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
            0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
            0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
            0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
        ]
        let sample: [UInt8] = [
            0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
            0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
        ]
        // 12-byte placeholder IV/key for ChaCha (only HP is asserted here).
        let protector = try SuiteProtector<QUICCryptoProvider>.make(
            suite: .chaCha20Poly1305,
            key: [UInt8](repeating: 0, count: 32),
            iv: [UInt8](repeating: 0, count: 12),
            hpKey: hpKey)
        let mask = try protector.headerProtectionMask(sample: sample)
        #expect(mask == [0xae, 0xfe, 0xfe, 0x7d, 0x03])
    }
}
