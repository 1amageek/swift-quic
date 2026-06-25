// DERSignatureTests.swift
// Byte-format oracle for the dual-build TLS signature provider: it asserts that the
// ECDSA signatures `QUICTLSSignature` emits are DER `SEQUENCE { INTEGER r, INTEGER
// s }` (RFC 8446 §4.4.3) and BYTE-IDENTICAL to CryptoKit's `derRepresentation` — the
// encoding go-libp2p / rust-libp2p require on the wire. The shared
// `DefaultCryptoProvider` emits RAW `r || s`; these tests would FAIL against that
// raw scheme, which is exactly the interop bug this provider fixes.

import Testing
import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto
import QUICTLSSignature

@Suite("QUICTLSSignature DER ECDSA byte-format oracle")
struct DERSignatureTests {

    // MARK: - DER structural assertions

    @Test("P-256 signatures are DER SEQUENCE { INTEGER, INTEGER }, not 64-byte raw")
    func p256IsDER() throws {
        let key = try DERSignatureP256.generateSigningKey()
        let message = [UInt8]("der-format-p256".utf8)
        let sig = try DERSignatureP256.sign(message.span, with: key)

        // A raw P-256 signature is exactly 64 bytes; a DER one starts with 0x30
        // (SEQUENCE) and is variable-length (typically 70-72 bytes).
        #expect(sig.first == 0x30, "DER ECDSA signature must begin with SEQUENCE (0x30)")
        #expect(sig.count != 64, "DER ECDSA signature must NOT be 64-byte raw r||s")
        // CryptoKit must accept it as a DER ECDSA signature.
        let der = try P256.Signing.ECDSASignature(derRepresentation: Data(sig))
        #expect(!der.rawRepresentation.isEmpty)
    }

    @Test("P-384 signatures are DER SEQUENCE, not 96-byte raw")
    func p384IsDER() throws {
        let key = try DERSignatureP384.generateSigningKey()
        let message = [UInt8]("der-format-p384".utf8)
        let sig = try DERSignatureP384.sign(message.span, with: key)

        #expect(sig.first == 0x30, "DER ECDSA signature must begin with SEQUENCE (0x30)")
        #expect(sig.count != 96, "DER ECDSA signature must NOT be 96-byte raw r||s")
        let der = try P384.Signing.ECDSASignature(derRepresentation: Data(sig))
        #expect(!der.rawRepresentation.isEmpty)
    }

    // MARK: - Byte-identity with CryptoKit derRepresentation

    @Test("ECDSADERConversion.encode is byte-identical to CryptoKit derRepresentation (P-256)")
    func p256DEREncodingMatchesCryptoKit() throws {
        // Sign with CryptoKit, take its raw r||s, feed it through our DER encoder,
        // and assert the bytes match CryptoKit's own derRepresentation exactly.
        for index in 0..<32 {
            let ck = P256.Signing.PrivateKey()
            let message = Data("oracle-\(index)".utf8)
            let signature = try ck.signature(for: message)
            let raw = [UInt8](signature.rawRepresentation)   // 64-byte r||s
            #expect(raw.count == 64)

            let ours = try ECDSADERConversion.encode(raw: raw, scalarLength: 32)
            let cryptoKitDER = [UInt8](signature.derRepresentation)
            #expect(ours == cryptoKitDER, "DER encoding must be byte-identical to CryptoKit")
        }
    }

    @Test("ECDSADERConversion round-trips raw -> DER -> raw (P-256, P-384)")
    func roundTripPreservesRaw() throws {
        for index in 0..<16 {
            let p256 = P256.Signing.PrivateKey()
            let raw256 = [UInt8](try p256.signature(for: Data("rt256-\(index)".utf8)).rawRepresentation)
            let der256 = try ECDSADERConversion.encode(raw: raw256, scalarLength: 32)
            let back256 = try #require(ECDSADERConversion.decode(der: der256, scalarLength: 32))
            #expect(back256 == raw256)

            let p384 = P384.Signing.PrivateKey()
            let raw384 = [UInt8](try p384.signature(for: Data("rt384-\(index)".utf8)).rawRepresentation)
            let der384 = try ECDSADERConversion.encode(raw: raw384, scalarLength: 48)
            let back384 = try #require(ECDSADERConversion.decode(der: der384, scalarLength: 48))
            #expect(back384 == raw384)
        }
    }

    // MARK: - Sign/verify round-trip + cross-verify against CryptoKit

    @Test("P-256 sign/verify round-trips and CryptoKit verifies the DER signature")
    func p256SignVerifyAndCryptoKitCrossVerify() throws {
        let key = try DERSignatureP256.generateSigningKey()
        let verifying = DERSignatureP256.verifyingKey(for: key)
        let message = [UInt8]("cross-verify-p256".utf8)
        let sig = try DERSignatureP256.sign(message.span, with: key)

        // Our verifier accepts.
        let ourOK = DERSignatureP256.isValid(signature: sig.span, for: message.span, with: verifying)
        #expect(ourOK)

        // CryptoKit (the interop oracle) accepts the same DER signature.
        let pubBytes = DERSignatureP256.rawRepresentation(of: verifying)   // 65-byte x963
        let ckPub = try P256.Signing.PublicKey(x963Representation: Data(pubBytes))
        let ckSig = try P256.Signing.ECDSASignature(derRepresentation: Data(sig))
        #expect(ckPub.isValidSignature(ckSig, for: Data(message)))
    }

    // MARK: - Fail-closed negatives

    @Test("A tampered DER signature is explicitly rejected (no silent accept)")
    func tamperedRejected() throws {
        let key = try DERSignatureP256.generateSigningKey()
        let verifying = DERSignatureP256.verifyingKey(for: key)
        let message = [UInt8]("tamper".utf8)
        var sig = try DERSignatureP256.sign(message.span, with: key)
        sig[sig.count - 1] ^= 0xFF
        let rejected = DERSignatureP256.isValid(signature: sig.span, for: message.span, with: verifying)
        #expect(!rejected)
    }

    @Test("A 64-byte raw r||s is NOT accepted as a DER signature (decode returns nil)")
    func rawIsNotDER() throws {
        let raw = [UInt8](repeating: 0x01, count: 64)
        #expect(ECDSADERConversion.decode(der: raw, scalarLength: 32) == nil,
                "raw r||s must not decode as DER SEQUENCE")
    }

    @Test("encode rejects a wrong-length raw signature (fail-closed)")
    func encodeRejectsBadLength() {
        let tooShort = [UInt8](repeating: 0x02, count: 40)
        #expect(throws: P2PCoreCrypto.CryptoError.self) {
            _ = try ECDSADERConversion.encode(raw: tooShort, scalarLength: 32)
        }
    }
}
