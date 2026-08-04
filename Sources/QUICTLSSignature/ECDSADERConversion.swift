// ECDSADERConversion.swift
// Raw `r || s` <-> DER `SEQUENCE { INTEGER r, INTEGER s }` for the TLS 1.3
// CertificateVerify wire (RFC 8446 §4.4.3) and the X.509 ECDSA self-signature.
//
// The shared `DefaultCryptoProvider` emits ECDSA signatures in *raw* `r || s`
// p1363 form (64 B for P-256, 96 B for P-384) — correct for Noise / libp2p but
// NOT for the TLS 1.3 CertificateVerify wire, which mandates the DER
// `SEQUENCE { INTEGER r, INTEGER s }` encoding. This converter sits between the
// raw seam signature and the DER wire bytes:
//
// - `encode` — split the fixed-width `r` and `s` halves and DER-encode them via
//   `P2PCoreDER.DERWriter.encodeInteger`, which applies the ASN.1 INTEGER
//   minimal/sign-bit rules (strip a leading `0x00`, prepend `0x00` when the high
//   bit is set). The output is BYTE-IDENTICAL to CryptoKit's `derRepresentation`
//   / the host `QUICDERSignatureP256` for the same `r || s`.
// - `decode` — DER-decode the wire signature back to `r` and `s` (re-padded to
//   the fixed scalar width) so the raw seam verifier can check it.
//
// FAIL-CLOSED: a backend signature that is not exactly `2 * scalarLength` bytes
// is an explicit typed throw from `encode` (a backend invariant violation, never
// silently re-shaped); a malformed DER signature is an explicit `nil` from
// `decode` (the caller treats it as an invalid signature, never a silent accept).
//
// Dual-built (host + Embedded): no Foundation, no `any`, no swift-crypto. The DER
// codec is `P2PCoreDER`, which is itself Embedded-clean.

import P2PCoreBytes
import P2PCoreCrypto
import P2PCoreDER

/// Fixed-width-scalar <-> DER conversion for the QUIC TLS ECDSA signature schemes.
///
/// `scalarLength` is the curve's coordinate size (32 for P-256, 48 for P-384); a
/// raw ECDSA signature is exactly `2 * scalarLength` bytes (`r || s`).
public enum ECDSADERConversion {

    /// DER-encode a raw `r || s` signature as `SEQUENCE { INTEGER r, INTEGER s }`.
    /// `DERWriter.encodeInteger` applies the ASN.1 minimal/sign-bit rules, so the
    /// output matches CryptoKit's `derRepresentation` byte-for-byte.
    ///
    /// - Throws: ``CryptoError/invalidLength`` if `raw` is not `2 * scalarLength`
    ///   bytes (the backend must emit a fixed-width p1363 signature; anything else
    ///   is a backend invariant violation, never silently re-shaped).
    public static func encode(raw: [UInt8], scalarLength: Int) throws(CryptoError) -> [UInt8] {
        do {
            return try ECDSASignatureDER.encode(
                rawRepresentation: raw,
                scalarByteCount: scalarLength
            )
        } catch .invalidECDSASignatureLength(let expected, let actual) {
            throw .invalidLength(expected: expected, actual: actual)
        } catch {
            throw .providerFailure
        }
    }

    /// DER-decode `SEQUENCE { INTEGER r, INTEGER s }` back to a fixed-width raw
    /// `r || s` of `2 * scalarLength` bytes. Each INTEGER is left-padded (or its
    /// ASN.1 sign byte dropped) to exactly `scalarLength` bytes.
    ///
    /// Returns `nil` for any malformed DER, trailing bytes, or an integer that
    /// does not fit `scalarLength` (e.g. an over-long `r`/`s`) — the caller treats
    /// this as an invalid signature (`false`), never a silent accept.
    public static func decode(der: [UInt8], scalarLength: Int) -> [UInt8]? {
        do {
            return try ECDSASignatureDER.decode(
                derRepresentation: der,
                scalarByteCount: scalarLength
            )
        } catch {
            return nil
        }
    }
}
