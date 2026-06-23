/// Routes the live `QUICPacketProtector` packet codec path through the
/// Embedded-clean ``PacketParsingCore``.
///
/// `PacketDecoder`/`PacketEncoder` (in QUICCore) are generic over the
/// `Data`-based `PacketOpenerProtocol`/`PacketSealerProtocol`; that generic path
/// stays for callers that supply arbitrary openers (e.g. the test mock openers).
/// The real connection path always uses the concrete ``QUICPacketProtector``,
/// which wraps a ``SuiteProtector`` — so these concrete-type overloads are
/// statically preferred at the `PacketProcessor` call sites and forward the
/// parse/serialize + header-protection/decrypt work to the `[UInt8]`-based core,
/// converting `Data` <-> `[UInt8]` at the boundary and mapping
/// ``PacketParsingError`` back onto the historical `PacketCodecError` /
/// `QUICError` / `HeaderValidationError` so behaviour (incl. the coalesced-skip
/// `noOpener`/`decryptionFailed` semantics) is unchanged.

import Foundation
import QUICCore
import QUICConnectionCore
import QUICPacketProtectionCore

// MARK: - Error mapping

extension PacketParsingError {
    /// Maps a core parsing error onto the adapter's historical error surface so
    /// the existing `PacketProcessor` catch clauses keep matching (no silent
    /// fallback: every failure throws a distinct, faithful error).
    func asAdapterError() -> Error {
        switch self {
        case .insufficientData:
            return PacketCodecError.insufficientData
        case .invalidPacketFormat(let message):
            return PacketCodecError.invalidPacketFormat(message)
        case .noProtector:
            return PacketCodecError.noOpener
        case .packetTooLarge(let size, let maxSize):
            return PacketCodecError.packetTooLarge(size: size, maxSize: maxSize)
        case .frame(let frameError):
            // Frame decode failures propagate as-is (the prior path surfaced the
            // FrameCodecError from the frame codec unchanged).
            return frameError
        case .headerValidation(let validationError):
            // The prior decode path propagated HeaderValidationError raw.
            return validationError
        case .conversion(let conversionError):
            return conversionError
        case .protection(let protectionError):
            switch protectionError {
            case .crypto(.authenticationFailure), .ciphertextTooShort:
                // AEAD open/seal failure: the prior QUICPacketProtector.open threw
                // QUICError.decryptionFailed (which the coalesced-skip path catches).
                return QUICError.decryptionFailed
            default:
                // Header-protection / IV / sample failures: surface the typed
                // CryptoError, matching QUICPacketProtector's header-protection path.
                return protectionError.asCryptoError
            }
        }
    }
}

// MARK: - PacketDecoder concrete overloads (route through PacketParsingCore)

extension PacketDecoder {

    /// Decodes a packet with a single ``QUICPacketProtector`` opener, routing the
    /// parse/decrypt through ``PacketParsingCore``. Concrete-type overload of the
    /// generic `decodePacket(data:dcidLength:opener:largestPN:)`.
    public func decodePacket(
        data: Data,
        dcidLength: Int,
        opener: QUICPacketProtector?,
        largestPN: UInt64 = 0
    ) throws -> ParsedPacket {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }
        let bytes = [UInt8](data)
        let isLongHeader = (bytes[0] & 0x80) != 0

        let core: ParsedPacketCore
        do {
            if isLongHeader {
                core = try PacketParsingCore.parseLongHeaderPacket(
                    bytes: bytes, protector: opener?.protector, largestPN: largestPN)
            } else {
                let hp = opener?.protector
                core = try PacketParsingCore.parseShortHeaderPacket(
                    bytes: bytes,
                    dcidLength: dcidLength,
                    largestPN: largestPN,
                    headerProtectionProtector: hp,
                    openerSelector: { _ throws(PacketParsingError) in hp })
            }
        } catch {
            throw error.asAdapterError()
        }
        return ParsedPacket(fromCore: core)
    }

    /// Decodes a 1-RTT packet selecting the AEAD opener by Key Phase bit
    /// (RFC 9001 §6), routing through ``PacketParsingCore``. Concrete-type overload
    /// of the generic key-phase-aware `decodePacket(...)`.
    public func decodePacket(
        data: Data,
        dcidLength: Int,
        longHeaderOpener: QUICPacketProtector?,
        headerProtectionOpener: QUICPacketProtector?,
        shortHeaderOpenerSelector: (_ keyPhase: UInt8) throws -> QUICPacketProtector?,
        largestPN: UInt64 = 0
    ) throws -> ParsedPacket {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }
        let bytes = [UInt8](data)
        let isLongHeader = (bytes[0] & 0x80) != 0

        if isLongHeader {
            let core: ParsedPacketCore
            do {
                core = try PacketParsingCore.parseLongHeaderPacket(
                    bytes: bytes, protector: longHeaderOpener?.protector, largestPN: largestPN)
            } catch {
                throw error.asAdapterError()
            }
            return ParsedPacket(fromCore: core)
        }

        // Short header: the selector closure may throw the adapter's errors; capture
        // the first such error so it can be rethrown faithfully after the core call.
        var selectorError: Error?
        let core: ParsedPacketCore
        do {
            core = try PacketParsingCore.parseShortHeaderPacket(
                bytes: bytes,
                dcidLength: dcidLength,
                largestPN: largestPN,
                headerProtectionProtector: headerProtectionOpener?.protector,
                openerSelector: { phase throws(PacketParsingError) in
                    do {
                        return try shortHeaderOpenerSelector(phase)?.protector
                    } catch {
                        selectorError = error
                        // Signal "no opener" to abort the core; the captured error
                        // is rethrown below so the caller sees its original error.
                        return nil
                    }
                })
        } catch {
            if let selectorError { throw selectorError }
            throw error.asAdapterError()
        }
        return ParsedPacket(fromCore: core)
    }
}

// MARK: - PacketEncoder concrete overloads (route through PacketParsingCore)

extension PacketEncoder {

    /// Encodes a Long Header packet with a concrete ``QUICPacketProtector`` sealer,
    /// routing the serialize/protect through ``PacketParsingCore``.
    public func encodeLongHeaderPacket(
        frames: [Frame],
        header: LongHeader,
        packetNumber: UInt64,
        sealer: QUICPacketProtector,
        maxPacketSize: Int = PacketEncoder.defaultMTU,
        padToMinimum: Bool = true
    ) throws -> Data {
        do {
            let bytes = try PacketParsingCore.serializeLongHeaderPacket(
                frames: frames,
                header: header,
                packetNumber: packetNumber,
                protector: sealer.protector,
                maxPacketSize: maxPacketSize,
                padToMinimum: padToMinimum)
            return Data(bytes)
        } catch {
            throw error.asAdapterError()
        }
    }

    /// Encodes a Short Header packet with a concrete ``QUICPacketProtector`` sealer,
    /// routing the serialize/protect through ``PacketParsingCore``.
    public func encodeShortHeaderPacket(
        frames: [Frame],
        header: ShortHeader,
        packetNumber: UInt64,
        sealer: QUICPacketProtector,
        maxPacketSize: Int = PacketEncoder.defaultMTU
    ) throws -> Data {
        do {
            let bytes = try PacketParsingCore.serializeShortHeaderPacket(
                frames: frames,
                header: header,
                packetNumber: packetNumber,
                protector: sealer.protector,
                maxPacketSize: maxPacketSize)
            return Data(bytes)
        } catch {
            throw error.asAdapterError()
        }
    }
}

// MARK: - ParsedPacket bridge

extension ParsedPacket {
    /// Builds the adapter `ParsedPacket` from the core's parsed value.
    init(fromCore core: ParsedPacketCore) {
        self.init(
            header: core.header,
            packetNumber: core.packetNumber,
            frames: core.frames,
            encryptionLevel: core.encryptionLevel,
            packetSize: core.packetSize,
            keyPhase: core.keyPhase)
    }
}
