/// TLS 1.3 (EC)DHE key exchange (RFC 8446 §4.2.8), Embedded-clean.
///
/// Generates an ephemeral key pair and computes the (EC)DHE shared secret for the
/// negotiated named group (X25519, P-256 — the only groups QUIC's TLS 1.3 uses)
/// through the ``P2PCoreCrypto/KeyAgreement`` seam instead of swift-crypto. The
/// shared secret is returned as raw `[UInt8]` — the (EC)DHE input the key schedule
/// extracts the handshake secret from.
///
/// The named group selects the seam scheme via a closed `switch` on
/// ``NamedGroup``; groups QUIC does not negotiate (P-384, P-521, X448) throw
/// ``TLSKeyExchangeCoreError/unsupportedGroup`` and stay in the adapter (no silent
/// fallback). This mirrors the legacy `KeyExchange.generate(for:)`, which accepted
/// only `x25519` / `secp256r1`.
///
/// Wire encodings (identical to the legacy swift-crypto path):
/// - X25519: 32-byte raw public key.
/// - P-256: 65-byte X9.62 uncompressed point (`0x04 || x || y`).
///
/// The provider's `KeyAgreement.publicKey(rawRepresentation:)` interprets these
/// bytes (raw for X25519, x963 for P-256) so the seam path is byte-for-byte the
/// same key material as before the refactor.
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = QUICFoundationProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto

/// TLS 1.3 (EC)DHE key exchange parameterised by the crypto provider seam.
public enum TLSKeyExchange<C: CryptoProvider> {

    /// The wire-format public-key length for `group`, or `nil` if the group is
    /// not expressible through QUIC's DH key-agreement seam.
    public static func publicKeyLength(for group: NamedGroup) -> Int? {
        switch group {
        case .x25519:    return 32
        case .secp256r1: return 65
        case .secp384r1, .secp521r1, .x448:
            return nil
        }
    }

    /// An ephemeral key pair for one of the seam's DH groups, with its public-key
    /// wire bytes already serialised.
    public struct EphemeralKeyPair: Sendable {
        /// The negotiated named group.
        public let group: NamedGroup
        /// The public-key bytes to place in the `key_share` extension.
        public let publicKeyBytes: [UInt8]
        /// The private-key raw bytes (used to recompute the shared secret).
        public let privateKeyBytes: [UInt8]
    }

    // MARK: - Generation

    /// Generates a fresh ephemeral key pair for `group`.
    ///
    /// - Throws: ``TLSKeyExchangeCoreError/unsupportedGroup`` for groups outside
    ///   X25519 / P-256, or ``TLSKeyExchangeCoreError/crypto`` if the seam RNG
    ///   fails.
    public static func generate(
        for group: NamedGroup
    ) throws(TLSKeyExchangeCoreError) -> EphemeralKeyPair {
        switch group {
        case .x25519:
            return try generate(group: group, agreement: C.X25519.self)
        case .secp256r1:
            return try generate(group: group, agreement: C.P256Agreement.self)
        case .secp384r1, .secp521r1, .x448:
            throw .unsupportedGroup
        }
    }

    private static func generate<A: KeyAgreement>(
        group: NamedGroup,
        agreement: A.Type
    ) throws(TLSKeyExchangeCoreError) -> EphemeralKeyPair {
        let privateKey: A.PrivateKey
        do {
            privateKey = try A.generatePrivateKey()
        } catch {
            throw .crypto(error)
        }
        let publicKey = A.publicKey(for: privateKey)
        return EphemeralKeyPair(
            group: group,
            publicKeyBytes: A.rawRepresentation(of: publicKey),
            privateKeyBytes: A.rawRepresentation(of: privateKey)
        )
    }

    // MARK: - Shared Secret

    /// Computes the (EC)DHE shared secret between `privateKeyBytes` and the peer's
    /// `peerPublicKeyBytes` for `group`.
    ///
    /// - Returns: The raw shared-secret bytes (32 for X25519 / P-256).
    /// - Throws: ``TLSKeyExchangeCoreError/unsupportedGroup`` for non-seam groups,
    ///   ``TLSKeyExchangeCoreError/invalidPublicKeyLength`` for a wrong-length peer
    ///   key, or ``TLSKeyExchangeCoreError/crypto`` for a seam failure (never a
    ///   silent empty/garbage return).
    public static func sharedSecret(
        group: NamedGroup,
        privateKeyBytes: Span<UInt8>,
        peerPublicKeyBytes: Span<UInt8>
    ) throws(TLSKeyExchangeCoreError) -> [UInt8] {
        switch group {
        case .x25519:
            return try sharedSecret(
                agreement: C.X25519.self,
                privateKeyBytes: privateKeyBytes,
                peerPublicKeyBytes: peerPublicKeyBytes,
                expectedPublicKeyLength: 32
            )
        case .secp256r1:
            return try sharedSecret(
                agreement: C.P256Agreement.self,
                privateKeyBytes: privateKeyBytes,
                peerPublicKeyBytes: peerPublicKeyBytes,
                expectedPublicKeyLength: 65
            )
        case .secp384r1, .secp521r1, .x448:
            throw .unsupportedGroup
        }
    }

    private static func sharedSecret<A: KeyAgreement>(
        agreement: A.Type,
        privateKeyBytes: Span<UInt8>,
        peerPublicKeyBytes: Span<UInt8>,
        expectedPublicKeyLength: Int
    ) throws(TLSKeyExchangeCoreError) -> [UInt8] {
        guard peerPublicKeyBytes.count == expectedPublicKeyLength else {
            throw .invalidPublicKeyLength(
                expected: expectedPublicKeyLength,
                actual: peerPublicKeyBytes.count
            )
        }
        let privateKey: A.PrivateKey
        let peerPublicKey: A.PublicKey
        do {
            privateKey = try A.privateKey(rawRepresentation: privateKeyBytes)
            peerPublicKey = try A.publicKey(rawRepresentation: peerPublicKeyBytes)
            return try A.sharedSecret(privateKey: privateKey, peerPublicKey: peerPublicKey)
        } catch {
            throw .crypto(error)
        }
    }
}
