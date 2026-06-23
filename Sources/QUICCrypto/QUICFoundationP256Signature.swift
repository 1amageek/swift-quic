/// ECDSA P-256 (SHA-256) for the `QUICFoundationProvider` signature seam.
///
/// swift-crypto / CryptoKit backend, byte-identical to the legacy
/// `TLSSignature` / `SigningKey.p256` path for TLS 1.3 CertificateVerify:
///
/// - Signing key raw representation = 32-byte raw scalar.
/// - Verifying key raw representation = 65-byte X9.62 uncompressed point
///   (`x963Representation`).
/// - **Signatures are DER-encoded** (`derRepresentation`) — the TLS 1.3 wire
///   format for ECDSA CertificateVerify (RFC 8446 §4.2.3). The TLS-internal
///   provider must produce the DER bytes the legacy path produced so existing
///   CertificateVerify vectors stay byte-identical.
///
/// CryptoKit hashes the message with SHA-256 internally. A signing failure throws
/// ``P2PCoreCrypto/CryptoError/providerFailure``; an invalid signature is an
/// explicit `false` from `isValid` (no silent fallback).

import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// ECDSA over P-256 for TLS. Conforms `P2PCoreCrypto.SignatureScheme`.
public enum QUICFoundationP256Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable {
        let key: P256.Signing.PrivateKey
    }

    public struct VerifyingKey: Sendable {
        let key: P256.Signing.PublicKey
    }

    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        SigningKey(key: P256.Signing.PrivateKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        do {
            return SigningKey(key: try P256.Signing.PrivateKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P256.Signing.PublicKey(
                x963Representation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 65, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(key: signingKey.key.publicKey)
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        [UInt8](signingKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        [UInt8](verifyingKey.key.x963Representation)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            let signature = try signingKey.key.signature(for: message.providerData())
            return [UInt8](signature.derRepresentation)
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        do {
            let sig = try P256.Signing.ECDSASignature(derRepresentation: signature.providerData())
            return verifyingKey.key.isValidSignature(sig, for: message.providerData())
        } catch {
            return false
        }
    }
}
