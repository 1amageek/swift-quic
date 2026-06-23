/// `Data`-based convenience surface for the moved TLS extension types.
///
/// Restores the historical non-throwing `encode() -> Data` / `decode(from: Data)`
/// API and `Data`-accepting initializers on the Embedded-clean extension types,
/// plus the `any TLSExtensionValue` accessor used by the adapter's
/// `findExtension`. This file is Foundation-only adapter glue.

import Foundation
import QUICTLSCore
import P2PCoreBytes

// MARK: - TLSExtension (Data)

extension TLSExtension {
    /// The `quicTransportParameters` payload as `Data`.
    public static func quicTransportParameters(_ data: Data) -> TLSExtension {
        .quicTransportParameters([UInt8](data))
    }

    /// An `unknown` extension from `Data`.
    public static func unknown(type: UInt16, data: Data) -> TLSExtension {
        .unknown(type: type, data: [UInt8](data))
    }

    /// Encode the extension (type + length + data) as `Data`.
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }

    /// Decode an extension from a `Data`-backed reader, advancing the reader's cursor.
    ///
    /// Re-encodes the single extension as a one-element extension block and decodes
    /// through the core's `[UInt8]` path, so the context-dependent variant
    /// selection (key_share / supported_versions / pre_shared_key) stays in one
    /// place and the cursor is advanced exactly past the extension.
    public static func decode(from reader: inout TLSReader) throws -> TLSExtension {
        let type = try reader.readUInt16()
        let data = try reader.readVector16()
        var writer = ByteWriter(reservingCapacity: 4 + data.count)
        writer.writeUInt16(type)
        do {
            try writer.writeVector16([UInt8](data))
        } catch {
            throw TLSDecodeError.invalidFormat("extension data exceeds length bound")
        }
        let decoded = try decodeExtensions(from: writer.finishArray())
        guard let first = decoded.first else {
            throw TLSDecodeError.invalidFormat("extension block decoded to no extensions")
        }
        return first
    }

    /// Decode an extension from a `Data`-backed reader in NewSessionTicket context.
    public static func decodeForNewSessionTicket(from reader: inout TLSReader) throws -> TLSExtension {
        let type = try reader.readUInt16()
        let data = try reader.readVector16()
        var writer = ByteWriter(reservingCapacity: 4 + data.count)
        writer.writeUInt16(type)
        do {
            try writer.writeVector16([UInt8](data))
        } catch {
            throw TLSDecodeError.invalidFormat("extension data exceeds length bound")
        }
        // Decode the single re-framed extension through the NewSessionTicket path.
        var coreReader = ByteReader(writer.finishArray())
        do {
            return try decodeForNewSessionTicket(from: &coreReader)
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    /// Decode multiple extensions from a `Data` blob.
    public static func decodeExtensions(from data: Data) throws -> [TLSExtension] {
        do { return try decodeExtensions(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

/// Returns the underlying extension value as an existential.
///
/// Adapter-only: the Embedded-clean core deliberately omits this accessor (it
/// would require an `any` existential). Used by `findExtension`.
func extensionValue(_ ext: TLSExtension) -> any TLSExtensionValue {
    switch ext {
    case .serverName(let v): return v
    case .supportedGroups(let v): return v
    case .signatureAlgorithms(let v): return v
    case .alpn(let v): return v
    case .preSharedKey(let v): return v
    case .earlyData(let v): return v
    case .supportedVersions(let v): return v
    case .pskKeyExchangeModes(let v): return v
    case .keyShare(let v): return v
    case .quicTransportParameters(let data): return QUICTransportParametersExtension(data: data)
    case .unknown(let type, let data): return UnknownExtension(type: type, data: data)
    }
}

// MARK: - Unknown / QUIC Transport Parameters value placeholders

/// Placeholder for unknown extensions (adapter-only existential conformer).
public struct UnknownExtension: TLSExtensionValue {
    public static var extensionType: TLSExtensionType { fatalError("Unknown extension has no type") }
    public let type: UInt16
    public let data: [UInt8]

    public init(type: UInt16, data: [UInt8]) {
        self.type = type
        self.data = data
    }

    public init(type: UInt16, data: Data) {
        self.type = type
        self.data = [UInt8](data)
    }

    public func encodeBytes() -> [UInt8] { data }
}

/// QUIC transport parameters extension value (type 0x0039, adapter-only conformer).
public struct QUICTransportParametersExtension: TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .quicTransportParameters }
    public let data: [UInt8]

    public init(data: [UInt8]) {
        self.data = data
    }

    public init(data: Data) {
        self.data = [UInt8](data)
    }

    public var dataValue: Data { Data(data) }

    public func encodeBytes() -> [UInt8] { data }

    public func encode() -> Data { Data(data) }
}

// MARK: - Per-extension Data encode/decode

extension ALPNExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ALPNExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension ServerNameExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ServerNameExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension SupportedGroupsExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedGroupsExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension SignatureAlgorithmsExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SignatureAlgorithmsExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension SupportedVersionsExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedVersionsExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension SupportedVersionsClientHello {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedVersionsClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension SupportedVersionsServerHello {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedVersionsServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension PskKeyExchangeModesExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> PskKeyExchangeModesExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension EarlyDataExtension {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decodeEmpty(from data: Data) throws -> EarlyDataExtension {
        do { return try decodeEmpty(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
    public static func decodeNewSessionTicket(from data: Data) throws -> EarlyDataExtension {
        do { return try decodeNewSessionTicket(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - KeyShare (Data)

extension KeyShareEntry {
    /// Creates a key share entry from a `Data` public key.
    public init(group: NamedGroup, keyExchange: Data) {
        self.init(group: group, keyExchange: [UInt8](keyExchange))
    }

    /// The public key bytes as `Data`.
    public var keyExchangeData: Data { Data(keyExchange) }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }

    /// Decode from a `Data`-backed reader, advancing the reader's cursor.
    public static func decode(from reader: inout TLSReader) throws -> KeyShareEntry {
        let groupValue = try reader.readUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw TLSDecodeError.invalidFormat("Unknown named group: \(groupValue)")
        }
        let keyExchange = try reader.readVector16()
        return KeyShareEntry(group: group, keyExchange: [UInt8](keyExchange))
    }
}

extension KeyShareExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> KeyShareExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
    public static func decodeClientHello(from data: Data) throws -> KeyShareClientHello {
        do { return try decodeClientHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
    public static func decodeServerHello(from data: Data) throws -> KeyShareServerHello {
        do { return try decodeServerHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension KeyShareClientHello {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> KeyShareClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension KeyShareServerHello {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> KeyShareServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension KeyShareHelloRetryRequest {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decode(from data: Data) throws -> KeyShareHelloRetryRequest {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - PreSharedKey (Data)

extension PskIdentity {
    /// Creates a PSK identity from a `Data` identity.
    public init(identity: Data, obfuscatedTicketAge: UInt32) {
        self.init(identity: [UInt8](identity), obfuscatedTicketAge: obfuscatedTicketAge)
    }

    /// The PSK identity as `Data`.
    public var identityData: Data { Data(identity) }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }

    /// Decode from a `Data`-backed reader, advancing the reader's cursor.
    public static func decode(from reader: inout TLSReader) throws -> PskIdentity {
        let identity = try reader.readVector16()
        let obfuscatedAge = try reader.readUInt32()
        return PskIdentity(identity: [UInt8](identity), obfuscatedTicketAge: obfuscatedAge)
    }
}

extension OfferedPsks {
    /// Creates offered PSKs from `Data` binders.
    public init(identities: [PskIdentity], binders: [Data]) {
        self.init(identities: identities, binders: binders.map { [UInt8]($0) })
    }

    /// The binders as `Data` values.
    public var bindersData: [Data] { binders.map { Data($0) } }

    /// The encoded identities part for binder computation as `Data`.
    public var encodedIdentitiesData: Data { Data(encodedIdentities) }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> OfferedPsks {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension SelectedPsk {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decode(from data: Data) throws -> SelectedPsk {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension PreSharedKeyExtension {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public static func decodeClientHello(from data: Data) throws -> PreSharedKeyExtension {
        do { return try decodeClientHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
    public static func decodeServerHello(from data: Data) throws -> PreSharedKeyExtension {
        do { return try decodeServerHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}
