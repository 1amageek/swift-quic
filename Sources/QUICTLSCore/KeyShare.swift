/// TLS 1.3 Key Share Extension (RFC 8446 Section 4.2.8)
///
/// In ClientHello:
/// ```
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
/// ```
///
/// In ServerHello:
/// ```
/// struct {
///     KeyShareEntry server_share;
/// } KeyShareServerHello;
/// ```
///
/// KeyShareEntry:
/// ```
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
/// ```

import P2PCoreBytes

// MARK: - Key Share Entry

/// A key share entry containing a named group and public key
public struct KeyShareEntry: Sendable {
    /// The named group (curve) for this key share
    public let group: NamedGroup

    /// The public key bytes
    public let keyExchange: [UInt8]

    public init(group: NamedGroup, keyExchange: [UInt8]) {
        self.group = group
        self.keyExchange = keyExchange
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 4 + keyExchange.count)
        writer.writeUInt16(group.rawValue)
        try writer.wWriteVector16(keyExchange)
        return writer.finishArray()
    }

    public static func decode(from reader: inout ByteReader) throws(TLSWireError) -> KeyShareEntry {
        let groupValue = try reader.wReadUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw TLSWireError.invalidFormat("Unknown named group: \(groupValue)")
        }
        let keyExchange = try reader.wReadVector16()
        return KeyShareEntry(group: group, keyExchange: keyExchange)
    }
}

// MARK: - Key Share Extension (wrapper)

/// Key share extension (can be client or server variant)
public enum KeyShareExtension: Sendable, TLSExtensionValue {
    case clientHello(KeyShareClientHello)
    case serverHello(KeyShareServerHello)
    case helloRetryRequest(KeyShareHelloRetryRequest)

    public static var extensionType: TLSExtensionType { .keyShare }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        switch self {
        case .clientHello(let ext): return try ext.encodeBytes()
        case .serverHello(let ext): return try ext.encodeBytes()
        case .helloRetryRequest(let ext): return ext.encodeBytes()
        }
    }

    /// Decode - context determines which variant
    /// Note: Caller should use specific decode methods based on message type
    public static func decode(from data: [UInt8]) throws(TLSWireError) -> KeyShareExtension {
        // Default to ClientHello parsing (has 2-byte length prefix for list)
        // ServerHello has no length prefix, just group + key_exchange
        // HRR has just 2 bytes (NamedGroup)

        // Try to detect: if data starts with a valid 2-byte length that matches remaining,
        // it's likely ClientHello format
        if data.count >= 2 {
            let possibleLength = Int(data[0]) << 8 | Int(data[1])
            if possibleLength == data.count - 2 {
                return .clientHello(try KeyShareClientHello.decode(from: data))
            }
        }

        // If exactly 2 bytes, it's HelloRetryRequest format (just NamedGroup)
        if data.count == 2 {
            return .helloRetryRequest(try KeyShareHelloRetryRequest.decode(from: data))
        }

        // Otherwise assume ServerHello format (group + key_exchange)
        return .serverHello(try KeyShareServerHello.decode(from: data))
    }

    public static func decodeClientHello(from data: [UInt8]) throws(TLSWireError) -> KeyShareClientHello {
        try KeyShareClientHello.decode(from: data)
    }

    public static func decodeServerHello(from data: [UInt8]) throws(TLSWireError) -> KeyShareServerHello {
        try KeyShareServerHello.decode(from: data)
    }
}

// MARK: - Client Hello Variant

/// Key share extension for ClientHello
public struct KeyShareClientHello: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .keyShare }

    /// List of key shares offered by the client
    public let clientShares: [KeyShareEntry]

    public init(clientShares: [KeyShareEntry]) {
        self.clientShares = clientShares
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var entriesData = [UInt8]()
        for entry in clientShares {
            entriesData.append(contentsOf: try entry.encodeBytes())
        }

        var writer = ByteWriter(reservingCapacity: 2 + entriesData.count)
        try writer.wWriteVector16(entriesData)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> KeyShareClientHello {
        var reader = ByteReader(data)
        let entriesData = try reader.wReadVector16()

        var entries: [KeyShareEntry] = []
        var entryReader = ByteReader(entriesData)
        while !entryReader.isAtEnd {
            entries.append(try KeyShareEntry.decode(from: &entryReader))
        }

        return KeyShareClientHello(clientShares: entries)
    }

    /// Find a key share for a specific group
    public func keyShare(for group: NamedGroup) -> KeyShareEntry? {
        clientShares.first { $0.group == group }
    }
}

// MARK: - Server Hello Variant

/// Key share extension for ServerHello
public struct KeyShareServerHello: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .keyShare }

    /// The server's selected key share
    public let serverShare: KeyShareEntry

    public init(serverShare: KeyShareEntry) {
        self.serverShare = serverShare
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        try serverShare.encodeBytes()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> KeyShareServerHello {
        var reader = ByteReader(data)
        let entry = try KeyShareEntry.decode(from: &reader)
        return KeyShareServerHello(serverShare: entry)
    }
}

// MARK: - Hello Retry Request Variant

/// Key share extension for HelloRetryRequest (only contains selected group)
public struct KeyShareHelloRetryRequest: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .keyShare }

    /// The group the server wants the client to use
    public let selectedGroup: NamedGroup

    public init(selectedGroup: NamedGroup) {
        self.selectedGroup = selectedGroup
    }

    public func encodeBytes() -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 2)
        writer.writeUInt16(selectedGroup.rawValue)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> KeyShareHelloRetryRequest {
        var reader = ByteReader(data)
        let groupValue = try reader.wReadUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw TLSWireError.invalidFormat("Unknown named group: \(groupValue)")
        }
        return KeyShareHelloRetryRequest(selectedGroup: group)
    }
}
