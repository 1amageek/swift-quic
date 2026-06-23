/// TLS 1.3 Server Name Indication Extension (RFC 6066 Section 3)
///
/// ```
/// struct {
///     NameType name_type;
///     select (name_type) {
///         case host_name: HostName;
///     } name;
/// } ServerName;
///
/// struct {
///     ServerName server_name_list<1..2^16-1>
/// } ServerNameList;
/// ```
///
/// Embedded-clean: hostnames are validated/decoded with the Foundation-free
/// `String(validating:as:)`, which rejects malformed UTF-8 (preserving the
/// historical `String(data:encoding:.utf8)` behaviour of yielding a `nil`
/// hostName for invalid bytes).

import P2PCoreBytes

// MARK: - Server Name Extension

/// Server Name Indication (SNI) extension
public struct ServerNameExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .serverName }

    /// Name type for DNS hostname
    private static let hostNameType: UInt8 = 0

    /// The server hostname
    public let hostName: String?

    public init(hostName: String?) {
        self.hostName = hostName
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        guard let hostName = hostName else {
            // Empty extension for ServerHello acknowledgment
            return []
        }

        let hostNameData = [UInt8](hostName.utf8)

        var serverNameData = [UInt8]()
        serverNameData.reserveCapacity(3 + hostNameData.count)
        // name_type (1 byte)
        serverNameData.append(Self.hostNameType)
        // HostName length (2 bytes)
        serverNameData.append(UInt8((hostNameData.count >> 8) & 0xFF))
        serverNameData.append(UInt8(hostNameData.count & 0xFF))
        // HostName
        serverNameData.append(contentsOf: hostNameData)

        var writer = ByteWriter(reservingCapacity: 2 + serverNameData.count)
        try writer.wWriteVector16(serverNameData)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> ServerNameExtension {
        // Empty data means ServerHello acknowledgment
        if data.isEmpty {
            return ServerNameExtension(hostName: nil)
        }

        var reader = ByteReader(data)
        let serverNameListData = try reader.wReadVector16()

        if serverNameListData.isEmpty {
            return ServerNameExtension(hostName: nil)
        }

        var listReader = ByteReader(serverNameListData)
        let nameType = try listReader.wReadUInt8()

        guard nameType == Self.hostNameType else {
            throw TLSWireError.invalidFormat("Unknown name type: \(nameType)")
        }

        let hostNameData = try listReader.wReadVector16()
        let hostName = String(validating: hostNameData, as: UTF8.self)

        return ServerNameExtension(hostName: hostName)
    }
}
