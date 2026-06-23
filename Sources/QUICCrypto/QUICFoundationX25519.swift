/// X25519 ECDH for the `QUICFoundationProvider` key-agreement seam.
///
/// swift-crypto / CryptoKit backend, byte-identical to the legacy
/// `KeyExchange.x25519` path (32-byte raw private + public encodings, 32-byte
/// shared secret). Used by `QUICTLSCore.TLSKeyExchange` when the negotiated group
/// is `x25519`.
///
/// Key-agreement failure throws ``P2PCoreCrypto/CryptoError/keyAgreementFailure``
/// (no silent fallback).

import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// X25519 key agreement over swift-crypto. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum QUICFoundationX25519: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable {
        let key: Curve25519.KeyAgreement.PrivateKey
    }

    public struct PublicKey: Sendable {
        let key: Curve25519.KeyAgreement.PublicKey
    }

    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        PrivateKey(key: Curve25519.KeyAgreement.PrivateKey())
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        do {
            return PrivateKey(key: try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey {
        do {
            return PublicKey(key: try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        PublicKey(key: privateKey.key.publicKey)
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        [UInt8](privateKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        [UInt8](publicKey.key.rawRepresentation)
    }

    public static func sharedSecret(
        privateKey: PrivateKey,
        peerPublicKey: PublicKey
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            let secret = try privateKey.key.sharedSecretFromKeyAgreement(with: peerPublicKey.key)
            return secret.withUnsafeBytes { [UInt8]($0) }
        } catch {
            throw .keyAgreementFailure
        }
    }
}
