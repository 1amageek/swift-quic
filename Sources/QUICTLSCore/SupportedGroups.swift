/// TLS 1.3 Supported Groups Extension (RFC 8446 Section 4.2.7)
///
/// ```
/// struct {
///     NamedGroup named_group_list<2..2^16-1>;
/// } NamedGroupList;
/// ```

import P2PCoreBytes

// MARK: - Supported Groups Extension

/// Supported groups (named curves) extension
public struct SupportedGroupsExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .supportedGroups }

    /// List of supported named groups in preference order
    public let namedGroups: [NamedGroup]

    public init(namedGroups: [NamedGroup]) {
        self.namedGroups = namedGroups
    }

    /// Default supported groups for TLS 1.3
    public static var `default`: SupportedGroupsExtension {
        SupportedGroupsExtension(namedGroups: [
            .x25519,
            .secp256r1,
            .secp384r1
        ])
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var groupsData = [UInt8]()
        groupsData.reserveCapacity(namedGroups.count * 2)
        for group in namedGroups {
            groupsData.append(UInt8((group.rawValue >> 8) & 0xFF))
            groupsData.append(UInt8(group.rawValue & 0xFF))
        }

        var writer = ByteWriter(reservingCapacity: 2 + groupsData.count)
        try writer.wWriteVector16(groupsData)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> SupportedGroupsExtension {
        var reader = ByteReader(data)
        let groupsData = try reader.wReadVector16()

        guard groupsData.count >= 2 && groupsData.count % 2 == 0 else {
            throw TLSWireError.invalidFormat("Invalid supported groups length")
        }

        var groups: [NamedGroup] = []
        var groupReader = ByteReader(groupsData)
        while !groupReader.isAtEnd {
            let value = try groupReader.wReadUInt16()
            if let group = NamedGroup(rawValue: value) {
                groups.append(group)
            }
            // Unknown groups are ignored
        }

        return SupportedGroupsExtension(namedGroups: groups)
    }

    /// Check if a named group is supported
    public func supports(_ group: NamedGroup) -> Bool {
        namedGroups.contains(group)
    }

    /// Find the first mutually supported group
    public func findCommon(with other: SupportedGroupsExtension) -> NamedGroup? {
        for group in namedGroups {
            if other.supports(group) {
                return group
            }
        }
        return nil
    }
}
