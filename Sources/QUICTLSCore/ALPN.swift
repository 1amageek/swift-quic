/// TLS 1.3 Application-Layer Protocol Negotiation Extension (RFC 7301)
///
/// ```
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>
/// } ProtocolNameList;
///
/// opaque ProtocolName<1..2^8-1>;
/// ```
///
/// Embedded-clean: protocol names are validated with the Foundation-free
/// `String(validating:as:)`, which rejects malformed UTF-8 — entries that fail
/// validation are skipped, matching the historical `String(data:encoding:.utf8)`
/// behaviour.

import P2PCoreBytes

// MARK: - ALPN Extension

/// Application-Layer Protocol Negotiation extension
public struct ALPNExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .alpn }

    /// List of protocol names in preference order
    public let protocols: [String]

    public init(protocols: [String]) {
        self.protocols = protocols
    }

    /// ALPN for HTTP/3
    public static var h3: ALPNExtension {
        ALPNExtension(protocols: ["h3"])
    }

    /// ALPN for libp2p
    public static var libp2p: ALPNExtension {
        ALPNExtension(protocols: ["libp2p"])
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var protocolListData = [UInt8]()
        for proto in protocols {
            let protoData = [UInt8](proto.utf8)
            protocolListData.append(UInt8(protoData.count))
            protocolListData.append(contentsOf: protoData)
        }

        var writer = ByteWriter(reservingCapacity: 2 + protocolListData.count)
        try writer.wWriteVector16(protocolListData)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> ALPNExtension {
        var reader = ByteReader(data)
        let protocolListData = try reader.wReadVector16()

        var protocols: [String] = []
        var listReader = ByteReader(protocolListData)
        while !listReader.isAtEnd {
            let protoData = try listReader.wReadVector8()
            if let proto = String(validating: protoData, as: UTF8.self) {
                protocols.append(proto)
            }
        }

        return ALPNExtension(protocols: protocols)
    }

    /// Check if a protocol is supported
    public func supports(_ protocol: String) -> Bool {
        protocols.contains(`protocol`)
    }

    /// Find the first mutually supported protocol
    public func negotiate(with other: ALPNExtension) -> String? {
        for proto in protocols {
            if other.supports(proto) {
                return proto
            }
        }
        return nil
    }

    /// Get the selected protocol (for ServerHello - first in list)
    public var selectedProtocol: String? {
        protocols.first
    }
}
