/// TLS 1.3 Extensions (RFC 8446 Section 4.2)
///
/// Extensions have the format:
/// ```
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
///
/// Embedded-clean: ``TLSExtension`` is a closed enum (each case carries its
/// concrete value type), so the codec never uses an `any TLSExtensionValue`
/// existential. The `value` accessor and the generic `findExtension<T>(as?)`
/// lookup that required an existential live in the `QUICCrypto` adapter.

import P2PCoreBytes

// `TLSExtensionType` lives in `TLSExtensionType.swift` in this module.

// MARK: - Extension Value Protocol

/// Protocol for extension values.
///
/// Used as a generic constraint (`some`/`<T: TLSExtensionValue>`), never as an
/// existential — Embedded Swift forbids `any` values.
public protocol TLSExtensionValue: Sendable {
    static var extensionType: TLSExtensionType { get }
    func encodeBytes() throws(TLSWireError) -> [UInt8]
}

// MARK: - TLS Extension Enum

/// A TLS extension with its type and value
public enum TLSExtension: Sendable {
    case serverName(ServerNameExtension)
    case supportedGroups(SupportedGroupsExtension)
    case signatureAlgorithms(SignatureAlgorithmsExtension)
    case alpn(ALPNExtension)
    case preSharedKey(PreSharedKeyExtension)
    case earlyData(EarlyDataExtension)
    case supportedVersions(SupportedVersionsExtension)
    case pskKeyExchangeModes(PskKeyExchangeModesExtension)
    case keyShare(KeyShareExtension)
    case quicTransportParameters([UInt8])
    case unknown(type: UInt16, data: [UInt8])

    // MARK: - Properties

    /// The extension type
    public var extensionType: TLSExtensionType? {
        switch self {
        case .serverName: return .serverName
        case .supportedGroups: return .supportedGroups
        case .signatureAlgorithms: return .signatureAlgorithms
        case .alpn: return .alpn
        case .preSharedKey: return .preSharedKey
        case .earlyData: return .earlyData
        case .supportedVersions: return .supportedVersions
        case .pskKeyExchangeModes: return .pskKeyExchangeModes
        case .keyShare: return .keyShare
        case .quicTransportParameters: return .quicTransportParameters
        case .unknown: return nil
        }
    }

    /// The raw extension type value
    public var rawType: UInt16 {
        switch self {
        case .serverName: return TLSExtensionType.serverName.rawValue
        case .supportedGroups: return TLSExtensionType.supportedGroups.rawValue
        case .signatureAlgorithms: return TLSExtensionType.signatureAlgorithms.rawValue
        case .alpn: return TLSExtensionType.alpn.rawValue
        case .preSharedKey: return TLSExtensionType.preSharedKey.rawValue
        case .earlyData: return TLSExtensionType.earlyData.rawValue
        case .supportedVersions: return TLSExtensionType.supportedVersions.rawValue
        case .pskKeyExchangeModes: return TLSExtensionType.pskKeyExchangeModes.rawValue
        case .keyShare: return TLSExtensionType.keyShare.rawValue
        case .quicTransportParameters: return TLSExtensionType.quicTransportParameters.rawValue
        case .unknown(let type, _): return type
        }
    }

    // MARK: - Encoding

    /// Encode the extension (type + length + data)
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        let extensionData: [UInt8]
        switch self {
        case .serverName(let ext): extensionData = try ext.encodeBytes()
        case .supportedGroups(let ext): extensionData = try ext.encodeBytes()
        case .signatureAlgorithms(let ext): extensionData = try ext.encodeBytes()
        case .alpn(let ext): extensionData = try ext.encodeBytes()
        case .preSharedKey(let ext): extensionData = try ext.encodeBytes()
        case .earlyData(let ext): extensionData = ext.encodeBytes()
        case .supportedVersions(let ext): extensionData = try ext.encodeBytes()
        case .pskKeyExchangeModes(let ext): extensionData = try ext.encodeBytes()
        case .keyShare(let ext): extensionData = try ext.encodeBytes()
        case .quicTransportParameters(let data): extensionData = data
        case .unknown(_, let data): extensionData = data
        }

        var writer = ByteWriter(reservingCapacity: 4 + extensionData.count)
        writer.writeUInt16(rawType)
        try writer.wWriteVector16(extensionData)
        return writer.finishArray()
    }

    // MARK: - Decoding

    /// Decode an extension from a reader
    public static func decode(from reader: inout ByteReader) throws(TLSWireError) -> TLSExtension {
        let type = try reader.wReadUInt16()
        let data = try reader.wReadVector16()

        guard let extensionType = TLSExtensionType(rawValue: type) else {
            return .unknown(type: type, data: data)
        }

        switch extensionType {
        case .serverName:
            return .serverName(try ServerNameExtension.decode(from: data))
        case .supportedGroups:
            return .supportedGroups(try SupportedGroupsExtension.decode(from: data))
        case .signatureAlgorithms:
            return .signatureAlgorithms(try SignatureAlgorithmsExtension.decode(from: data))
        case .alpn:
            return .alpn(try ALPNExtension.decode(from: data))
        case .preSharedKey:
            // Note: Decoding context matters (ClientHello vs ServerHello)
            // Default to ClientHello; caller can use specific decode methods
            return .preSharedKey(try PreSharedKeyExtension.decodeClientHello(from: data))
        case .earlyData:
            // Early data in ClientHello/EncryptedExtensions is empty
            return .earlyData(try EarlyDataExtension.decodeEmpty(from: data))
        case .supportedVersions:
            return .supportedVersions(try SupportedVersionsExtension.decode(from: data))
        case .pskKeyExchangeModes:
            return .pskKeyExchangeModes(try PskKeyExchangeModesExtension.decode(from: data))
        case .keyShare:
            return .keyShare(try KeyShareExtension.decode(from: data))
        case .quicTransportParameters:
            return .quicTransportParameters(data)
        }
    }

    /// Decode an extension from a reader in NewSessionTicket context
    /// This handles early_data differently (contains max_early_data_size)
    public static func decodeForNewSessionTicket(from reader: inout ByteReader) throws(TLSWireError) -> TLSExtension {
        let type = try reader.wReadUInt16()
        let data = try reader.wReadVector16()

        guard let extensionType = TLSExtensionType(rawValue: type) else {
            return .unknown(type: type, data: data)
        }

        switch extensionType {
        case .earlyData:
            // In NewSessionTicket, early_data contains max_early_data_size (4 bytes)
            return .earlyData(try EarlyDataExtension.decodeNewSessionTicket(from: data))
        default:
            // Other extensions decode the same way
            return try decodeWithTypeAndData(extensionType: extensionType, data: data)
        }
    }

    /// Decode multiple extensions from a byte blob
    ///
    /// - Parameter data: The raw extensions data (without length prefix)
    /// - Returns: Array of decoded extensions
    /// - Throws: If decoding fails
    public static func decodeExtensions(from data: [UInt8]) throws(TLSWireError) -> [TLSExtension] {
        var reader = ByteReader(data)
        var extensions: [TLSExtension] = []
        while !reader.isAtEnd {
            let ext = try decode(from: &reader)
            extensions.append(ext)
        }
        return extensions
    }

    /// Helper to decode extension with known type and data
    private static func decodeWithTypeAndData(extensionType: TLSExtensionType, data: [UInt8]) throws(TLSWireError) -> TLSExtension {
        switch extensionType {
        case .serverName:
            return .serverName(try ServerNameExtension.decode(from: data))
        case .supportedGroups:
            return .supportedGroups(try SupportedGroupsExtension.decode(from: data))
        case .signatureAlgorithms:
            return .signatureAlgorithms(try SignatureAlgorithmsExtension.decode(from: data))
        case .alpn:
            return .alpn(try ALPNExtension.decode(from: data))
        case .preSharedKey:
            return .preSharedKey(try PreSharedKeyExtension.decodeClientHello(from: data))
        case .earlyData:
            return .earlyData(try EarlyDataExtension.decodeEmpty(from: data))
        case .supportedVersions:
            return .supportedVersions(try SupportedVersionsExtension.decode(from: data))
        case .pskKeyExchangeModes:
            return .pskKeyExchangeModes(try PskKeyExchangeModesExtension.decode(from: data))
        case .keyShare:
            return .keyShare(try KeyShareExtension.decode(from: data))
        case .quicTransportParameters:
            return .quicTransportParameters(data)
        }
    }
}

// MARK: - Convenience Factory Methods

extension TLSExtension {
    /// Create a supported_versions extension for ClientHello
    public static func supportedVersionsClient(_ versions: [UInt16]) -> TLSExtension {
        .supportedVersions(.clientHello(SupportedVersionsClientHello(versions: versions)))
    }

    /// Create a supported_versions extension for ServerHello
    public static func supportedVersionsServer(_ version: UInt16) -> TLSExtension {
        .supportedVersions(.serverHello(SupportedVersionsServerHello(selectedVersion: version)))
    }

    /// Create a key_share extension for ClientHello
    public static func keyShareClient(_ entries: [KeyShareEntry]) -> TLSExtension {
        .keyShare(.clientHello(KeyShareClientHello(clientShares: entries)))
    }

    /// Create a key_share extension for ServerHello
    public static func keyShareServer(_ entry: KeyShareEntry) -> TLSExtension {
        .keyShare(.serverHello(KeyShareServerHello(serverShare: entry)))
    }

    /// Create an ALPN extension
    public static func alpnProtocols(_ protocols: [String]) -> TLSExtension {
        .alpn(ALPNExtension(protocols: protocols))
    }

    /// Create a supported_groups extension
    public static func supportedGroupsList(_ groups: [NamedGroup]) -> TLSExtension {
        .supportedGroups(SupportedGroupsExtension(namedGroups: groups))
    }

    /// Create a signature_algorithms extension
    public static func signatureAlgorithmsList(_ schemes: [SignatureScheme]) -> TLSExtension {
        .signatureAlgorithms(SignatureAlgorithmsExtension(supportedSignatureAlgorithms: schemes))
    }

    /// Create a psk_key_exchange_modes extension
    public static func pskKeyExchangeModesList(_ modes: [PskKeyExchangeMode]) -> TLSExtension {
        .pskKeyExchangeModes(PskKeyExchangeModesExtension(keModes: modes))
    }

    /// Create an early_data extension for ClientHello
    public static func earlyDataClient() -> TLSExtension {
        .earlyData(.clientHello)
    }

    /// Create an early_data extension for EncryptedExtensions
    public static func earlyDataServer() -> TLSExtension {
        .earlyData(.encryptedExtensions)
    }

    /// Create a pre_shared_key extension for ClientHello
    public static func preSharedKeyClient(_ offered: OfferedPsks) -> TLSExtension {
        .preSharedKey(.clientHello(offered))
    }

    /// Create a pre_shared_key extension for ServerHello
    public static func preSharedKeyServer(selectedIdentity: UInt16) -> TLSExtension {
        .preSharedKey(.serverHello(SelectedPsk(selectedIdentity: selectedIdentity)))
    }
}
