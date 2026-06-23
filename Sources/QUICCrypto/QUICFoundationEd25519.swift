/// Ed25519 (EdDSA) for the `QUICFoundationProvider` signature seam.
///
/// swift-crypto / CryptoKit backend, byte-identical to the legacy
/// `SigningKey.ed25519` path for TLS 1.3 CertificateVerify:
///
/// - Signing key raw representation = 32-byte seed.
/// - Verifying key raw representation = 32-byte raw public key.
/// - Signatures are the 64-byte raw EdDSA signature (CryptoKit's
///   `signature(for:)` output / wire format).
///
/// Ed25519 is a pure (PureEdDSA) scheme: it hashes the full message internally,
/// no external pre-hash. A signing failure throws
/// ``P2PCoreCrypto/CryptoError/providerFailure``; an invalid signature is an
/// explicit `false` from `isValid` (no silent fallback).

import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// Ed25519 signatures for TLS. Conforms `P2PCoreCrypto.SignatureScheme`.
public enum QUICFoundationEd25519: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable {
        let key: Curve25519.Signing.PrivateKey
    }

    public struct VerifyingKey: Sendable {
        let key: Curve25519.Signing.PublicKey
    }

    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        SigningKey(key: Curve25519.Signing.PrivateKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        do {
            return SigningKey(key: try Curve25519.Signing.PrivateKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try Curve25519.Signing.PublicKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(key: signingKey.key.publicKey)
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        [UInt8](signingKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        [UInt8](verifyingKey.key.rawRepresentation)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            return [UInt8](try signingKey.key.signature(for: message.providerData()))
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        verifyingKey.key.isValidSignature(signature.providerData(), for: message.providerData())
    }
}
