/// ECDSA P-256 (SHA-256) DER signature scheme for the QUIC TLS 1.3 handshake.
///
/// swift-crypto / CryptoKit backend, byte-identical to the legacy
/// `TLSSignature` / `SigningKey.p256` path for TLS 1.3 CertificateVerify:
///
/// - Signing key raw representation = 32-byte raw scalar.
/// - Verifying key raw representation = 65-byte X9.62 uncompressed point
///   (`x963Representation`).
/// - **Signatures are DER-encoded** (`derRepresentation`) — the TLS 1.3 wire
///   format for ECDSA CertificateVerify (RFC 8446 §4.2.3). The shared
///   `P2PCrypto.FoundationCryptoProvider` emits *raw* `r||s` ECDSA signatures
///   (correct for Noise/libp2p, WRONG for the TLS wire), so the QUIC composite
///   provider (``QUICCryptoProvider``) overrides only `P256Signature`/`P384Signature`
///   with these DER schemes; every other primitive comes from the shared provider.
///   This keeps the CertificateVerify wire bytes byte-identical to the pre-unify
///   path (pinned by `KeyExchangeSignatureSeamDifferentialTests`).
///
/// CryptoKit hashes the message with SHA-256 internally. A signing failure throws
/// ``P2PCoreCrypto/CryptoError/providerFailure``; an invalid signature is an
/// explicit `false` from `isValid` (no silent fallback).

import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// ECDSA over P-256 for the QUIC TLS handshake (DER signatures). Conforms
/// `P2PCoreCrypto.SignatureScheme`.
public enum QUICDERSignatureP256: P2PCoreCrypto.SignatureScheme {
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
                rawRepresentation: Data(rawRepresentation.quicDERArray())))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P256.Signing.PublicKey(
                x963Representation: Data(rawRepresentation.quicDERArray())))
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
            let signature = try signingKey.key.signature(for: Data(message.quicDERArray()))
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
            let sig = try P256.Signing.ECDSASignature(derRepresentation: Data(signature.quicDERArray()))
            return verifyingKey.key.isValidSignature(sig, for: Data(message.quicDERArray()))
        } catch {
            return false
        }
    }
}
