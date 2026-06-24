/// Unified concrete packet protector — host adapter.
///
/// `QUICPacketProtector` is the single concrete type that the connection and
/// codec layers hold in place of the former `any PacketOpener` / `any PacketSealer`
/// existentials. It wraps one ``SuiteProtector`` specialised at
/// `C = QUICCryptoProvider` and conforms to both ``PacketOpener`` and
/// ``PacketSealer`` (i.e. ``PacketOpenerProtocol`` and ``PacketSealerProtocol``),
/// so a single value can both open and seal packets for one derived key.
///
/// RFC 9001 §5.1 derives the same key material for both directions of a single
/// secret; the opener and the sealer for a given level/phase therefore wrap the
/// identical `SuiteProtector`. Keeping one concrete type (rather than two
/// existentials) is what lets the generic ``SuiteProtector`` flow end-to-end
/// through `CryptoContext` / `KeyPhaseContext` / `KeyPhaseManager` / the codec
/// without `any`.
///
/// This is the host (non-Embedded) adapter: its public API is `Data`-based so the
/// existing call sites and tests compile unchanged, but all crypto routes through
/// the `SuiteProtector<QUICCryptoProvider>` value (which itself goes through
/// the `CryptoProvider` / `HeaderProtectionProvider` seam).

import Foundation
import QUICCore
import QUICPacketProtectionCore
import P2PCrypto

/// A concrete QUIC packet protector that both opens and seals packets for one
/// derived key, wrapping a ``SuiteProtector`` at `C = QUICCryptoProvider`.
public struct QUICPacketProtector: PacketOpener, PacketSealer, Sendable {
    /// The underlying generic, Embedded-clean suite protector.
    public let protector: SuiteProtector<QUICCryptoProvider>

    /// AEAD requires a 12-byte IV for QUIC (RFC 9001 §5.3).
    public static let ivLength = 12

    /// Wraps an existing suite protector.
    public init(protector: SuiteProtector<QUICCryptoProvider>) {
        self.protector = protector
    }

    /// Builds a protector from derived key material, dispatching on the negotiated
    /// cipher suite so the correct AEAD is used (no hardcoded suite).
    public init(keyMaterial: KeyMaterial) throws {
        self.protector = try makeSuiteProtector(from: keyMaterial)
    }

    // MARK: - PacketOpenerProtocol

    public func open(ciphertext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        do {
            let plaintext = try protector.open(
                [UInt8](ciphertext), packetNumber: packetNumber, header: [UInt8](header))
            return Data(plaintext)
        } catch {
            // RFC 9001: AEAD open failure (incl. tag mismatch) MUST be reported,
            // never a silent garbage/empty return.
            throw QUICError.decryptionFailed
        }
    }

    public func removeHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        do {
            let (fb, pn) = try protector.removeHeaderProtection(
                sample: [UInt8](sample), firstByte: firstByte,
                packetNumberBytes: [UInt8](packetNumberBytes))
            return (fb, Data(pn))
        } catch {
            throw error.asCryptoError
        }
    }

    // MARK: - PacketSealerProtocol

    public func seal(plaintext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        do {
            let ciphertext = try protector.seal(
                [UInt8](plaintext), packetNumber: packetNumber, header: [UInt8](header))
            return Data(ciphertext)
        } catch {
            throw error.asCryptoError
        }
    }

    public func applyHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        do {
            let (fb, pn) = try protector.applyHeaderProtection(
                sample: [UInt8](sample), firstByte: firstByte,
                packetNumberBytes: [UInt8](packetNumberBytes))
            return (fb, Data(pn))
        } catch {
            throw error.asCryptoError
        }
    }
}
