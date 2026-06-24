/// Differential tests for the seam-routed TLS 1.3 HANDSHAKE crypto:
/// (EC)DHE key agreement and the CertificateVerify signature sign/verify.
///
/// Asserts that the Embedded-clean `QUICTLSCore.TLSKeyExchange<C>` and
/// `QUICTLSCore.TLSSignature{Signer,Verifier}<C>` specialised at
/// `C = QUICCryptoProvider` produce results byte-for-byte / behaviour-identical
/// to the legacy direct-swift-crypto paths (`KeyExchange`, `TLSSignature` /
/// `SigningKey` / `VerificationKey`):
///
///  1. Shared-secret equality for X25519 / P-256 (same key pair, both paths).
///  2. CertificateVerify signed-input bytes equality (the 64-space prefix +
///     context string + transcript hash, RFC 8446 §4.4.3).
///  3. Cross-verification: the legacy verifier accepts core-produced signatures
///     and the core verifier accepts legacy-produced signatures (signing is
///     randomised for ECDSA/Ed25519, so equality of bytes is not asserted —
///     verify-roundtrip + cross-verify is the oracle).
///  4. Negative: a tampered signature / wrong key is an explicit `false`, never a
///     silent accept.
///
/// This is the explicit byte-level oracle for the handshake-crypto seam slice.

import Testing
import Foundation
import Crypto
import P2PCoreBytes
@testable import QUICCrypto
import QUICTLSCore
import P2PCrypto

@Suite("TLS Key Exchange + Signature Seam Differential")
struct KeyExchangeSignatureSeamDifferentialTests {

    private typealias Provider = QUICCryptoProvider

    // MARK: - (EC)DHE shared-secret equality (legacy path == seam path)

    @Test("X25519 shared secret: legacy KeyExchange equals seam TLSKeyExchange")
    func x25519SharedSecretMatches() throws {
        let aliceRaw = Curve25519.KeyAgreement.PrivateKey()
        let bobRaw = Curve25519.KeyAgreement.PrivateKey()

        let alicePrivBytes = [UInt8](aliceRaw.rawRepresentation)
        let bobPubBytes = [UInt8](bobRaw.publicKey.rawRepresentation)

        // Legacy path: reconstruct alice's KeyExchange from the same private key,
        // agree with bob's public key.
        let aliceLegacy = KeyExchange.x25519(
            try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(alicePrivBytes)))
        let legacySecret = [UInt8](try aliceLegacy.sharedSecret(with: Data(bobPubBytes)).rawRepresentation)

        // Seam path: same private key bytes + same peer public-key bytes.
        let seamSecret = try TLSKeyExchange<Provider>.sharedSecret(
            group: .x25519,
            privateKeyBytes: alicePrivBytes.span,
            peerPublicKeyBytes: bobPubBytes.span)

        #expect(seamSecret == legacySecret)
        #expect(seamSecret.count == 32)
    }

    @Test("P-256 shared secret: legacy KeyExchange equals seam TLSKeyExchange")
    func p256SharedSecretMatches() throws {
        let aliceRaw = P256.KeyAgreement.PrivateKey()
        let bobRaw = P256.KeyAgreement.PrivateKey()

        let alicePrivBytes = [UInt8](aliceRaw.rawRepresentation)
        let bobPubBytes = [UInt8](bobRaw.publicKey.x963Representation)

        let aliceLegacy = KeyExchange.p256(
            try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(alicePrivBytes)))
        let legacySecret = [UInt8](try aliceLegacy.sharedSecret(with: Data(bobPubBytes)).rawRepresentation)

        let seamSecret = try TLSKeyExchange<Provider>.sharedSecret(
            group: .secp256r1,
            privateKeyBytes: alicePrivBytes.span,
            peerPublicKeyBytes: bobPubBytes.span)

        #expect(seamSecret == legacySecret)
        #expect(seamSecret.count == 32)
    }

    @Test("Seam key exchange: both peers agree on the same secret (roundtrip)")
    func seamRoundtripAgrees() throws {
        for group in [NamedGroup.x25519, .secp256r1] {
            let alice = try TLSKeyExchange<Provider>.generate(for: group)
            let bob = try TLSKeyExchange<Provider>.generate(for: group)

            let aliceSecret = try TLSKeyExchange<Provider>.sharedSecret(
                group: group,
                privateKeyBytes: alice.privateKeyBytes.span,
                peerPublicKeyBytes: bob.publicKeyBytes.span)
            let bobSecret = try TLSKeyExchange<Provider>.sharedSecret(
                group: group,
                privateKeyBytes: bob.privateKeyBytes.span,
                peerPublicKeyBytes: alice.publicKeyBytes.span)

            #expect(aliceSecret == bobSecret)
        }
    }

    @Test("Seam key exchange rejects groups QUIC does not negotiate")
    func seamRejectsUnsupportedGroups() {
        for group in [NamedGroup.secp384r1, .secp521r1, .x448] {
            #expect(throws: TLSKeyExchangeCoreError.unsupportedGroup) {
                _ = try TLSKeyExchange<Provider>.generate(for: group)
            }
        }
    }

    @Test("Seam key exchange rejects a wrong-length peer key (no silent fallback)")
    func seamRejectsBadPeerKeyLength() throws {
        let alice = try TLSKeyExchange<Provider>.generate(for: .x25519)
        let badPeer = [UInt8](repeating: 0x42, count: 16)
        #expect(throws: TLSKeyExchangeCoreError.self) {
            _ = try TLSKeyExchange<Provider>.sharedSecret(
                group: .x25519,
                privateKeyBytes: alice.privateKeyBytes.span,
                peerPublicKeyBytes: badPeer.span)
        }
    }

    // MARK: - CertificateVerify signed-input byte equality

    @Test("CertificateVerify signed input is byte-identical (legacy vs core builder)")
    func signedInputBytesMatch() {
        let transcriptHash = [UInt8](repeating: 0xAA, count: 32)

        for isServer in [true, false] {
            let legacy = CertificateVerify.constructSignatureContent(
                transcriptHash: Data(transcriptHash), isServer: isServer)
            let core = CertificateVerify.constructSignatureContentBytes(
                transcriptHash: transcriptHash, isServer: isServer)

            #expect([UInt8](legacy) == core)
            // RFC 8446 §4.4.3 shape: 64 spaces, then the context, 0x00, then hash.
            #expect(Array(core.prefix(64)) == [UInt8](repeating: 0x20, count: 64))
            #expect(Array(core.suffix(32)) == transcriptHash)
        }
    }

    // MARK: - CertificateVerify sign/verify cross-compat (ECDSA P-256)

    @Test("ECDSA P-256: core signature verifies via legacy + core verifier")
    func p256SignCrossVerify() throws {
        let signing = P256.Signing.PrivateKey()
        let privBytes = [UInt8](signing.rawRepresentation)
        let pubBytes = [UInt8](signing.publicKey.x963Representation)
        let transcriptHash = [UInt8](SHA256.hash(data: Data("transcript-p256".utf8)))

        // Core signs.
        let coreSig = try TLSSignatureSigner<Provider>.sign(
            algorithm: .ecdsa_secp256r1_sha256,
            privateKeyBytes: privBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)

        // Core verifier accepts.
        let coreOK = try TLSSignatureVerifier<Provider>.verify(
            signature: coreSig.span,
            algorithm: .ecdsa_secp256r1_sha256,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)
        #expect(coreOK == true)

        // Legacy verifier accepts the core (DER) signature over the same content.
        let signedContent = CertificateVerify.constructSignatureContent(
            transcriptHash: Data(transcriptHash), isServer: true)
        let legacyKey = try VerificationKey(
            publicKeyBytes: Data(pubBytes), scheme: .ecdsa_secp256r1_sha256)
        #expect(try legacyKey.verify(signature: Data(coreSig), for: signedContent) == true)
    }

    @Test("ECDSA P-256: legacy signature verifies via core verifier")
    func p256LegacySignCoreVerify() throws {
        let legacySigning = SigningKey.generateP256()
        guard case .p256(let p256Key) = legacySigning else {
            Issue.record("expected P-256 key")
            return
        }
        let pubBytes = [UInt8](p256Key.publicKey.x963Representation)
        let transcriptHash = [UInt8](SHA256.hash(data: Data("legacy-p256".utf8)))

        let signedContent = CertificateVerify.constructSignatureContent(
            transcriptHash: Data(transcriptHash), isServer: false)
        let legacySig = [UInt8](try legacySigning.sign(signedContent))

        let coreOK = try TLSSignatureVerifier<Provider>.verify(
            signature: legacySig.span,
            algorithm: .ecdsa_secp256r1_sha256,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: false)
        #expect(coreOK == true)
    }

    // MARK: - CertificateVerify sign/verify cross-compat (ECDSA P-384)

    @Test("ECDSA P-384: core signature verifies via legacy + core verifier")
    func p384SignCrossVerify() throws {
        let signing = P384.Signing.PrivateKey()
        let privBytes = [UInt8](signing.rawRepresentation)
        let pubBytes = [UInt8](signing.publicKey.x963Representation)
        let transcriptHash = [UInt8](SHA384.hash(data: Data("transcript-p384".utf8)))

        let coreSig = try TLSSignatureSigner<Provider>.sign(
            algorithm: .ecdsa_secp384r1_sha384,
            privateKeyBytes: privBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)

        let coreOK = try TLSSignatureVerifier<Provider>.verify(
            signature: coreSig.span,
            algorithm: .ecdsa_secp384r1_sha384,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)
        #expect(coreOK == true)

        let signedContent = CertificateVerify.constructSignatureContent(
            transcriptHash: Data(transcriptHash), isServer: true)
        let legacyKey = try VerificationKey(
            publicKeyBytes: Data(pubBytes), scheme: .ecdsa_secp384r1_sha384)
        #expect(try legacyKey.verify(signature: Data(coreSig), for: signedContent) == true)
    }

    // MARK: - CertificateVerify sign/verify cross-compat (Ed25519)

    @Test("Ed25519: core signature verifies via legacy + core verifier")
    func ed25519SignCrossVerify() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let privBytes = [UInt8](signing.rawRepresentation)
        let pubBytes = [UInt8](signing.publicKey.rawRepresentation)
        let transcriptHash = [UInt8](SHA256.hash(data: Data("transcript-ed25519".utf8)))

        let coreSig = try TLSSignatureSigner<Provider>.sign(
            algorithm: .ed25519,
            privateKeyBytes: privBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)

        let coreOK = try TLSSignatureVerifier<Provider>.verify(
            signature: coreSig.span,
            algorithm: .ed25519,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)
        #expect(coreOK == true)

        let signedContent = CertificateVerify.constructSignatureContent(
            transcriptHash: Data(transcriptHash), isServer: true)
        let legacyKey = try VerificationKey(
            publicKeyBytes: Data(pubBytes), scheme: .ed25519)
        #expect(try legacyKey.verify(signature: Data(coreSig), for: signedContent) == true)
    }

    @Test("Ed25519: legacy signature verifies via core verifier")
    func ed25519LegacySignCoreVerify() throws {
        let legacySigning = SigningKey.generateEd25519()
        guard case .ed25519(let edKey) = legacySigning else {
            Issue.record("expected Ed25519 key")
            return
        }
        let pubBytes = [UInt8](edKey.publicKey.rawRepresentation)
        let transcriptHash = [UInt8](SHA256.hash(data: Data("legacy-ed25519".utf8)))

        let signedContent = CertificateVerify.constructSignatureContent(
            transcriptHash: Data(transcriptHash), isServer: false)
        let legacySig = [UInt8](try legacySigning.sign(signedContent))

        let coreOK = try TLSSignatureVerifier<Provider>.verify(
            signature: legacySig.span,
            algorithm: .ed25519,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: false)
        #expect(coreOK == true)
    }

    // MARK: - Negative: explicit reject (no silent accept)

    @Test("Tampered signature is explicitly rejected (returns false)")
    func tamperedSignatureRejected() throws {
        let signing = P256.Signing.PrivateKey()
        let privBytes = [UInt8](signing.rawRepresentation)
        let pubBytes = [UInt8](signing.publicKey.x963Representation)
        let transcriptHash = [UInt8](SHA256.hash(data: Data("tamper".utf8)))

        var sig = try TLSSignatureSigner<Provider>.sign(
            algorithm: .ecdsa_secp256r1_sha256,
            privateKeyBytes: privBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)
        // Flip a byte.
        sig[sig.count - 1] ^= 0xFF

        let ok = try TLSSignatureVerifier<Provider>.verify(
            signature: sig.span,
            algorithm: .ecdsa_secp256r1_sha256,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)
        #expect(ok == false)
    }

    @Test("Wrong transcript hash is explicitly rejected (returns false)")
    func wrongTranscriptRejected() throws {
        let signing = P256.Signing.PrivateKey()
        let privBytes = [UInt8](signing.rawRepresentation)
        let pubBytes = [UInt8](signing.publicKey.x963Representation)
        let goodHash = [UInt8](SHA256.hash(data: Data("good".utf8)))
        let wrongHash = [UInt8](SHA256.hash(data: Data("wrong".utf8)))

        let sig = try TLSSignatureSigner<Provider>.sign(
            algorithm: .ecdsa_secp256r1_sha256,
            privateKeyBytes: privBytes.span,
            transcriptHash: goodHash.span,
            isServer: true)

        let ok = try TLSSignatureVerifier<Provider>.verify(
            signature: sig.span,
            algorithm: .ecdsa_secp256r1_sha256,
            publicKeyBytes: pubBytes.span,
            transcriptHash: wrongHash.span,
            isServer: true)
        #expect(ok == false)
    }

    @Test("Server-context signature does not verify under client context")
    func contextSeparationEnforced() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let privBytes = [UInt8](signing.rawRepresentation)
        let pubBytes = [UInt8](signing.publicKey.rawRepresentation)
        let transcriptHash = [UInt8](SHA256.hash(data: Data("ctx".utf8)))

        let serverSig = try TLSSignatureSigner<Provider>.sign(
            algorithm: .ed25519,
            privateKeyBytes: privBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: true)

        // Verifying the server signature as if it were a client one must fail.
        let ok = try TLSSignatureVerifier<Provider>.verify(
            signature: serverSig.span,
            algorithm: .ed25519,
            publicKeyBytes: pubBytes.span,
            transcriptHash: transcriptHash.span,
            isServer: false)
        #expect(ok == false)
    }

    @Test("RSA / non-seam schemes throw unsupportedScheme (no silent fallback)")
    func nonSeamSchemesThrow() {
        let hash = [UInt8](repeating: 0x11, count: 32)
        let key = [UInt8](repeating: 0x22, count: 32)
        for scheme in [SignatureScheme.rsa_pss_rsae_sha256, .rsa_pkcs1_sha256,
                       .ecdsa_secp521r1_sha512, .ed448] {
            #expect(throws: TLSSignatureCoreError.unsupportedScheme) {
                _ = try TLSSignatureVerifier<Provider>.verify(
                    signature: key.span, algorithm: scheme,
                    publicKeyBytes: key.span, transcriptHash: hash.span, isServer: true)
            }
        }
    }
}
