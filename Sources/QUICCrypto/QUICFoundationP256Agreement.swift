/// P-256 ECDH for the `QUICFoundationProvider` key-agreement seam.
///
/// swift-crypto / CryptoKit backend, byte-identical to the legacy
/// `KeyExchange.p256` path: private = 32-byte raw scalar, public = 65-byte X9.62
/// uncompressed point (`x963Representation`, the TLS `key_share` wire format),
/// shared secret = 32 bytes. Used by `QUICTLSCore.TLSKeyExchange` when the
/// negotiated group is `secp256r1`.
///
/// Key-agreement failure throws ``P2PCoreCrypto/CryptoError/keyAgreementFailure``
/// (no silent fallback).

import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// P-256 key agreement over swift-crypto. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum QUICFoundationP256Agreement: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable {
        let key: P256.KeyAgreement.PrivateKey
    }

    public struct PublicKey: Sendable {
        let key: P256.KeyAgreement.PublicKey
    }

    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        PrivateKey(key: P256.KeyAgreement.PrivateKey())
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        do {
            return PrivateKey(key: try P256.KeyAgreement.PrivateKey(
                rawRepresentation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey {
        do {
            return PublicKey(key: try P256.KeyAgreement.PublicKey(
                x963Representation: rawRepresentation.providerData()))
        } catch {
            throw .invalidLength(expected: 65, actual: rawRepresentation.count)
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
