/// Embedded-clean QUIC packet-protection key derivation (RFC 9001 §5.1–5.2),
/// routed through the `CryptoProvider.KeyDerivation` seam.
///
/// Provides `HKDF-Expand-Label` (TLS 1.3 / RFC 8446 §7.1) built on top of the
/// seam's raw `expand`, plus the QUIC packet key/iv/hp derivation and the initial
/// secret derivation from a Destination Connection ID. The `SymmetricKey`/`Data`
/// of the swift-crypto path are replaced by `[UInt8]`; HKDF is `C.HKDFSHA256`.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto

/// QUIC packet-protection key schedule over the crypto seam.
public enum QUICKeyDerivation<C: CryptoProvider> {

    // MARK: - HKDF-Expand-Label (RFC 8446 §7.1)

    /// `HKDF-Expand-Label(secret, label, context, length)` with the `"tls13 "`
    /// prefix (RFC 8446 §7.1), used by QUIC for "quic key"/"quic iv"/"quic hp"/
    /// "quic ku"/"client in"/"server in" (RFC 9001 §5).
    ///
    /// Constructs the `HkdfLabel` structure
    /// (`uint16 length || opaque label<7..255> || opaque context<0..255>`) with a
    /// `ByteWriter`, then calls the seam's `expand`.
    public static func expandLabel(
        secret: [UInt8],
        label: String,
        context: [UInt8],
        length: Int
    ) throws(PacketProtectionError) -> [UInt8] {
        let prefixedLabel = Array("tls13 \(label)".utf8)
        var writer = ByteWriter()
        writer.writeUInt16(UInt16(truncatingIfNeeded: length))
        writer.writeUInt8(UInt8(truncatingIfNeeded: prefixedLabel.count))
        writer.writeBytes(prefixedLabel)
        writer.writeUInt8(UInt8(truncatingIfNeeded: context.count))
        writer.writeBytes(context)
        let info = writer.finishArray()

        let kdf = C.HKDFSHA256()
        do {
            return try kdf.expand(prk: secret.span, info: info.span, length: length)
        } catch {
            throw .crypto(error)
        }
    }

    // MARK: - Initial secret (RFC 9001 §5.2)

    /// `initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)`.
    public static func initialSecret(
        connectionID: [UInt8],
        salt: [UInt8]
    ) -> [UInt8] {
        let kdf = C.HKDFSHA256()
        return kdf.extract(salt: salt.span, ikm: connectionID.span)
    }

    /// Derives the client/server initial secrets from the DCID and version salt
    /// (RFC 9001 §5.2): `{client,server}_initial_secret =
    /// HKDF-Expand-Label(initial_secret, "client in"/"server in", "", 32)`.
    public static func initialSecrets(
        connectionID: [UInt8],
        salt: [UInt8]
    ) throws(PacketProtectionError) -> (client: [UInt8], server: [UInt8]) {
        let initial = initialSecret(connectionID: connectionID, salt: salt)
        let client = try expandLabel(secret: initial, label: "client in", context: [], length: 32)
        let server = try expandLabel(secret: initial, label: "server in", context: [], length: 32)
        return (client, server)
    }

    // MARK: - Packet keys (RFC 9001 §5.1)

    /// Derives the (key, iv, hp) triple for `suite` from a traffic secret:
    /// - `quic key = HKDF-Expand-Label(secret, "quic key", "", key_len)`
    /// - `quic iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)`
    /// - `quic hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_len)`
    public static func packetKeys(
        secret: [UInt8],
        suite: QUICProtectionSuite
    ) throws(PacketProtectionError) -> (key: [UInt8], iv: [UInt8], hpKey: [UInt8]) {
        let keyLen = suite.keyLength
        let key = try expandLabel(secret: secret, label: "quic key", context: [], length: keyLen)
        let iv = try expandLabel(secret: secret, label: "quic iv", context: [], length: 12)
        let hpKey = try expandLabel(secret: secret, label: "quic hp", context: [], length: keyLen)
        return (key, iv, hpKey)
    }

    /// Builds a ``SuiteProtector`` directly from a traffic secret and suite,
    /// deriving keys via ``packetKeys(secret:suite:)`` and routing AEAD/HP through
    /// the seam.
    public static func protector(
        secret: [UInt8],
        suite: QUICProtectionSuite
    ) throws(PacketProtectionError) -> SuiteProtector<C> {
        let (key, iv, hpKey) = try packetKeys(secret: secret, suite: suite)
        return try SuiteProtector<C>.make(suite: suite, key: key, iv: iv, hpKey: hpKey)
    }

    /// Key update (RFC 9001 §6.1): `secret_next = HKDF-Expand-Label(secret, "quic ku", "", 32)`.
    public static func nextGenerationSecret(
        secret: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        try expandLabel(secret: secret, label: "quic ku", context: [], length: 32)
    }
}
