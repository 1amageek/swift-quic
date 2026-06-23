/// P-384 ECDH for the `QUICFoundationProvider` key-agreement seam.
///
/// swift-crypto / CryptoKit backend: private = 48-byte raw scalar, public =
/// 97-byte X9.62 uncompressed point (`x963Representation`, the TLS `key_share` wire
/// format), shared secret = 48 bytes. Completes the provider's key-agreement seam
/// (`QUICTLSCore.TLSKeyExchange` itself only negotiates X25519 / P-256 for QUIC,
/// but the provider conforms the full seam so it specialises cleanly).
///
/// Key-agreement failure throws ``P2PCoreCrypto/CryptoError/keyAgreementFailure``
/// (no silent fallback).

import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// P-384 key agreement over swift-crypto. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum QUICFoundationP384Agreement: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable {
        let key: P384.KeyAgreement.PrivateKey
    }

    public struct PublicKey: Sendable {
        let key: P384.KeyAgreement.PublicKey
    }

    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        PrivateKey(key: P384.KeyAgreement.PrivateKey())
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        do {
            return PrivateKey(key: try P384.KeyAgreement.PrivateKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 48, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey {
        do {
            return PublicKey(key: try P384.KeyAgreement.PublicKey(
                x963Representation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 97, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        PublicKey(key: privateKey.key.publicKey)
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        [UInt8](privateKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        [UInt8](publicKey.key.x963Representation)
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
