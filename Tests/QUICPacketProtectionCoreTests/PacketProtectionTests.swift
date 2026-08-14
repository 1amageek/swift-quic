import Testing
import NetworkingCore
import QUICWire
import QUICPacketProtectionCore

@Suite("RFC 9001 packet protection")
struct PacketProtectionTests {
    @Test("Retry integrity matches RFC 9001 Appendix A.4")
    func retryIntegrityVector() throws {
        let originalDestination = try ConnectionID(bytes: [
            0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        ])
        let packetWithoutTag: [UInt8] = [
            0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
            0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
            0x6f, 0x6b, 0x65, 0x6e,
        ]
        let expectedTag: [UInt8] = [
            0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
            0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
        ]
        let computed = try RetryIntegrityCore.compute(
            originalDestinationConnectionID: originalDestination,
            retryPacketWithoutTag: packetWithoutTag.span,
            version: .v1
        )
        #expect(computed == expectedTag)
        #expect(try RetryIntegrityCore.verify(
            tag: expectedTag.span,
            originalDestinationConnectionID: originalDestination,
            retryPacketWithoutTag: packetWithoutTag.span,
            version: .v1
        ))

        var forged = expectedTag
        forged[0] ^= 0x01
        #expect(try !RetryIntegrityCore.verify(
            tag: forged.span,
            originalDestinationConnectionID: originalDestination,
            retryPacketWithoutTag: packetWithoutTag.span,
            version: .v1
        ))
    }

    private static let clientKey: [UInt8] = [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    ]
    private static let clientIV: [UInt8] = [
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    ]
    private static let clientHeaderProtectionKey: [UInt8] = [
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    ]
    private static let clientSample: [UInt8] = [
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
    ]

    private func makeClientProtector() throws -> SuiteProtector {
        try SuiteProtector.make(
            suite: .aes128GCM,
            key: Self.clientKey,
            iv: Self.clientIV,
            hpKey: Self.clientHeaderProtectionKey
        )
    }

    @Test("AES header protection matches RFC 9001 Appendix A.2")
    func aesHeaderProtectionVector() throws {
        let protector = try makeClientProtector()
        #expect(
            try protector.headerProtectionMask(sample: Self.clientSample.span)
                == [0x43, 0x7b, 0x9a, 0xec, 0x36]
        )
    }

    @Test("header protection is self-inverse")
    func headerProtectionRoundTrip() throws {
        let protector = try makeClientProtector()
        let packetNumberBytes: [UInt8] = [0, 0, 0, 2]
        let protected = try protector.applyHeaderProtection(
            sample: Self.clientSample.span,
            firstByte: 0xc3,
            packetNumberBytes: packetNumberBytes
        )
        let unprotected = try protector.removeHeaderProtection(
            sample: Self.clientSample.span,
            firstByte: protected.firstByte,
            packetNumberBytes: protected.packetNumberBytes
        )
        #expect(unprotected.firstByte == 0xc3)
        #expect(unprotected.packetNumberBytes == packetNumberBytes)
    }

    @Test("AEAD authenticates payload and header")
    func authenticatedEncryptionRoundTrip() throws {
        let protector = try makeClientProtector()
        let plaintext = Array("RFC 9001 packet protection".utf8)
        let header: [UInt8] = [0xc0, 0, 0, 0, 1]
        let sealed = try protector.seal(
            plaintext.span,
            packetNumber: 2,
            header: header.span
        )
        #expect(
            try protector.open(
                sealed.span,
                packetNumber: 2,
                header: header.span
            ) == plaintext
        )

        var tampered = sealed
        tampered[tampered.count - 1] ^= 0xff
        #expect(throws: PacketProtectionError.self) {
            _ = try protector.open(
                tampered.span,
                packetNumber: 2,
                header: header.span
            )
        }
        #expect(throws: PacketProtectionError.self) {
            _ = try protector.open(
                sealed.span,
                packetNumber: 2,
                header: [0xc0, 0, 0, 0, 2].span
            )
        }
        #expect(throws: PacketProtectionError.self) {
            _ = try protector.open(
                sealed.span,
                packetNumber: 3,
                header: header.span
            )
        }
        #expect(throws: PacketProtectionError.ciphertextTooShort(minimum: 16, actual: 15)) {
            _ = try protector.open(
                [UInt8](repeating: 0, count: 15).span,
                packetNumber: 2,
                header: header.span
            )
        }
    }

    @Test("protector construction and samples enforce exact lengths")
    func protectorLengthValidation() throws {
        #expect(throws: PacketProtectionError.self) {
            _ = try SuiteProtector.make(
                suite: .aes128GCM,
                key: [UInt8](repeating: 0, count: 15),
                iv: [UInt8](repeating: 0, count: 12),
                hpKey: [UInt8](repeating: 0, count: 16)
            )
        }
        #expect(throws: PacketProtectionError.self) {
            _ = try SuiteProtector.make(
                suite: .aes128GCM,
                key: [UInt8](repeating: 0, count: 16),
                iv: [UInt8](repeating: 0, count: 11),
                hpKey: [UInt8](repeating: 0, count: 16)
            )
        }
        let protector = try makeClientProtector()
        #expect(throws: PacketProtectionError.insufficientSample(expected: 16, actual: 15)) {
            _ = try protector.headerProtectionMask(
                sample: [UInt8](repeating: 0, count: 15).span
            )
        }
    }

    @Test("Retry verification rejects a malformed tag length")
    func retryTagLengthValidation() throws {
        let cid = try ConnectionID(bytes: [1])
        #expect(throws: PacketProtectionError.self) {
            _ = try RetryIntegrityCore.verify(
                tag: [UInt8](repeating: 0, count: 15).span,
                originalDestinationConnectionID: cid,
                retryPacketWithoutTag: [0xFF].span,
                version: .v1
            )
        }
    }

    @Test("initial key derivation matches RFC 9001 Appendix A.1")
    func initialKeyDerivationVector() throws {
        let destinationConnectionID: [UInt8] = [
            0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        ]
        let salt: [UInt8] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a,
        ]
        let secrets = try QUICKeyDerivation.initialSecrets(
            connectionID: destinationConnectionID,
            salt: salt
        )
        let keys = try QUICKeyDerivation.packetKeys(
            secret: secrets.client,
            suite: .aes128GCM
        )
        #expect(keys.key == Self.clientKey)
        #expect(keys.iv == Self.clientIV)
        #expect(keys.hpKey == Self.clientHeaderProtectionKey)
    }

    @Test("ChaCha20 header protection matches RFC 9001 Appendix A.5")
    func chaCha20HeaderProtectionVector() throws {
        let headerProtectionKey: [UInt8] = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
            0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
            0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
            0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
        ]
        let sample: [UInt8] = [
            0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
            0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
        ]
        let protector = try SuiteProtector.make(
            suite: .chaCha20Poly1305,
            key: [UInt8](repeating: 0, count: 32),
            iv: [UInt8](repeating: 0, count: 12),
            hpKey: headerProtectionKey
        )
        #expect(
            try protector.headerProtectionMask(sample: sample.span)
                == [0xae, 0xfe, 0xfe, 0x7d, 0x03]
        )
    }
}
