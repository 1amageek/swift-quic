/// TLS 1.3 `HKDF-Expand-Label` and `Derive-Secret` (RFC 8446 §7.1), routed through
/// the `CryptoProvider.KeyDerivation` seam and generic over `C: CryptoProvider`.
///
/// Builds the `HkdfLabel` structure
/// (`uint16 length || opaque label<7..255> || opaque context<0..255>`) with the
/// `"tls13 "` prefix, then calls the seam's `expand`. The hash function (SHA-256 vs
/// SHA-384) is selected per `TLSHashAlgorithm`, matching the cipher suite.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto. `[UInt8]` in/out, typed
/// throws (closed `TLSKeyScheduleError`).
import P2PCoreBytes
import P2PCoreCrypto

/// HKDF-Expand-Label / Derive-Secret primitives over the crypto seam.
public enum TLSExpandLabel<C: CryptoProvider> {

    /// Builds the RFC 8446 §7.1 `HkdfLabel` byte structure for `label` (`"tls13 "`
    /// is prefixed internally), `context`, and the requested output `length`.
    ///
    /// This is the canonical wire layout shared by every TLS 1.3 / QUIC label and is
    /// kept byte-identical to the swift-crypto adapter path.
    public static func hkdfLabelBytes(label: String, context: [UInt8], length: Int) -> [UInt8] {
        let prefixedLabel = Array("tls13 \(label)".utf8)
        var writer = ByteWriter()
        // uint16 length
        writer.writeUInt16(UInt16(truncatingIfNeeded: length))
        // opaque label<7..255>
        writer.writeUInt8(UInt8(truncatingIfNeeded: prefixedLabel.count))
        writer.writeBytes(prefixedLabel)
        // opaque context<0..255>
        writer.writeUInt8(UInt8(truncatingIfNeeded: context.count))
        writer.writeBytes(context)
        return writer.finishArray()
    }

    /// `HKDF-Expand-Label(secret, label, context, length)` for the given hash
    /// algorithm.
    public static func expandLabel(
        secret: [UInt8],
        label: String,
        context: [UInt8],
        length: Int,
        hash: TLSHashAlgorithm
    ) throws(TLSKeyScheduleError) -> [UInt8] {
        let info = hkdfLabelBytes(label: label, context: context, length: length)
        do {
            switch hash {
            case .sha256:
                return try C.HKDFSHA256().expand(prk: secret.span, info: info.span, length: length)
            case .sha384:
                return try C.HKDFSHA384().expand(prk: secret.span, info: info.span, length: length)
            }
        } catch {
            throw .crypto(error)
        }
    }

    /// `Derive-Secret(secret, label, transcriptHash)` =
    /// `HKDF-Expand-Label(secret, label, Transcript-Hash, Hash.length)` (RFC 8446 §7.1).
    public static func deriveSecret(
        secret: [UInt8],
        label: String,
        transcriptHash: [UInt8],
        hash: TLSHashAlgorithm
    ) throws(TLSKeyScheduleError) -> [UInt8] {
        try expandLabel(
            secret: secret,
            label: label,
            context: transcriptHash,
            length: hash.digestLength,
            hash: hash
        )
    }

    /// `HKDF-Extract(salt, ikm)` for the given hash algorithm.
    public static func extract(salt: [UInt8], ikm: [UInt8], hash: TLSHashAlgorithm) -> [UInt8] {
        switch hash {
        case .sha256:
            return C.HKDFSHA256().extract(salt: salt.span, ikm: ikm.span)
        case .sha384:
            return C.HKDFSHA384().extract(salt: salt.span, ikm: ikm.span)
        }
    }

    /// `Transcript-Hash("")` — the hash of the empty string for the given algorithm.
    /// RFC 8446 §7.1 uses this as the context for the `"derived"` Derive-Secret steps.
    public static func emptyTranscriptHash(hash: TLSHashAlgorithm) -> [UInt8] {
        let empty = [UInt8]()
        switch hash {
        case .sha256:
            return C.SHA256.hash(empty.span)
        case .sha384:
            return C.SHA384.hash(empty.span)
        }
    }
}
