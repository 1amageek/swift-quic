/// TLS 1.3 PSK Key Exchange Modes Extension (RFC 8446 Section 4.2.9)
///
/// ```
/// enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
///
/// struct {
///     PskKeyExchangeMode ke_modes<1..255>;
/// } PskKeyExchangeModes;
/// ```
///
/// This extension is required when offering PSKs in ClientHello.
/// It indicates which key exchange modes the client supports:
/// - psk_ke: PSK-only (no forward secrecy)
/// - psk_dhe_ke: PSK with (EC)DHE (has forward secrecy)
///
/// TLS 1.3 MUST use psk_dhe_ke for QUIC (RFC 9001 Section 4.4).
///
/// `PskKeyExchangeMode` lives in `PskKeyExchangeMode.swift` in this module.

import P2PCoreBytes

// MARK: - PSK Key Exchange Modes Extension

/// PSK key exchange modes extension (ClientHello only)
public struct PskKeyExchangeModesExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .pskKeyExchangeModes }

    /// Supported key exchange modes
    public let keModes: [PskKeyExchangeMode]

    // MARK: - Initialization

    public init(keModes: [PskKeyExchangeMode]) {
        self.keModes = keModes
    }

    /// Default for QUIC: psk_dhe_ke only (required by RFC 9001)
    public static var quicDefault: PskKeyExchangeModesExtension {
        PskKeyExchangeModesExtension(keModes: [.psk_dhe_ke])
    }

    /// TLS default: both modes (prefer psk_dhe_ke)
    public static var tlsDefault: PskKeyExchangeModesExtension {
        PskKeyExchangeModesExtension(keModes: [.psk_dhe_ke, .psk_ke])
    }

    // MARK: - Encoding

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: keModes.count + 1)

        // ke_modes<1..255>
        var modesData = [UInt8]()
        for mode in keModes {
            modesData.append(mode.rawValue)
        }
        try writer.wWriteVector8(modesData)

        return writer.finishArray()
    }

    // MARK: - Decoding

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> PskKeyExchangeModesExtension {
        var reader = ByteReader(data)

        let modesData = try reader.wReadVector8()
        guard !modesData.isEmpty else {
            throw TLSWireError.invalidFormat("PskKeyExchangeModes: empty")
        }

        var keModes: [PskKeyExchangeMode] = []
        for byte in modesData {
            if let mode = PskKeyExchangeMode(rawValue: byte) {
                keModes.append(mode)
            }
            // Ignore unknown modes (forward compatibility)
        }

        guard !keModes.isEmpty else {
            throw TLSWireError.invalidFormat("PskKeyExchangeModes: no supported modes")
        }

        return PskKeyExchangeModesExtension(keModes: keModes)
    }
}

// MARK: - Convenience

extension PskKeyExchangeModesExtension {
    /// Check if psk_dhe_ke mode is supported
    public var supportsPskDheKe: Bool {
        keModes.contains(.psk_dhe_ke)
    }

    /// Check if psk_ke mode is supported
    public var supportsPskKe: Bool {
        keModes.contains(.psk_ke)
    }
}
