/// TLS 1.3 Pre-Shared Key Extension (RFC 8446 Section 4.2.11)
///
/// The "pre_shared_key" extension is used to negotiate the identity of the
/// pre-shared key to be used with a given handshake in association with
/// PSK key establishment.
///
/// ClientHello:
/// ```
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
///
/// opaque PskBinderEntry<32..255>;
///
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello: OfferedPsks;
///         case server_hello: uint16 selected_identity;
///     };
/// } PreSharedKeyExtension;
/// ```
///
/// The PSK binder computation (`PSKBinderHelper`), the `init(ticket:at:)`
/// convenience, and `SessionTicketData` are crypto/Date dependent and live in
/// the `QUICCrypto` adapter; this core file carries only the pure wire types.

import P2PCoreBytes

// MARK: - PSK Identity

/// A single PSK identity offered by the client
public struct PskIdentity: Sendable, Equatable {
    /// The PSK identity (ticket for resumption, or external PSK label)
    public let identity: [UInt8]

    /// Obfuscated ticket age in milliseconds
    /// For resumption: (time since ticket) + ticket_age_add
    /// For external PSK: 0
    public let obfuscatedTicketAge: UInt32

    public init(identity: [UInt8], obfuscatedTicketAge: UInt32) {
        self.identity = identity
        self.obfuscatedTicketAge = obfuscatedTicketAge
    }

    // MARK: - Encoding/Decoding

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: identity.count + 6)
        try writer.wWriteVector16(identity)
        writer.writeUInt32(obfuscatedTicketAge)
        return writer.finishArray()
    }

    public static func decode(from reader: inout ByteReader) throws(TLSWireError) -> PskIdentity {
        let identity = try reader.wReadVector16()
        let obfuscatedAge = try reader.wReadUInt32()
        return PskIdentity(identity: identity, obfuscatedTicketAge: obfuscatedAge)
    }
}

// MARK: - Offered PSKs (ClientHello)

/// PSKs offered in ClientHello pre_shared_key extension
public struct OfferedPsks: Sendable {
    /// List of PSK identities offered
    public let identities: [PskIdentity]

    /// Corresponding binders (HMAC over transcript)
    /// Must have same count as identities
    public var binders: [[UInt8]]

    public init(identities: [PskIdentity], binders: [[UInt8]] = []) {
        self.identities = identities
        self.binders = binders
    }

    // MARK: - Encoding

    /// Encode the offered PSKs
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 256)

        // identities<7..2^16-1>
        var identitiesData = [UInt8]()
        for identity in identities {
            identitiesData.append(contentsOf: try identity.encodeBytes())
        }
        try writer.wWriteVector16(identitiesData)

        // binders<33..2^16-1>
        var bindersData = [UInt8]()
        for binder in binders {
            // Each binder is a PskBinderEntry<32..255>
            bindersData.append(UInt8(binder.count))
            bindersData.append(contentsOf: binder)
        }
        try writer.wWriteVector16(bindersData)

        return writer.finishArray()
    }

    /// Encoded identities part (for binder computation)
    /// The binders will be computed separately
    ///
    /// `encodeBytes()` only throws on a wire-length overflow (an identity or the
    /// identities list exceeding its length prefix), a programmer-contract
    /// violation that the historical non-throwing `Data` path expressed as an
    /// integer-conversion trap. Surface it as a `fatalError` (a loud, non-silent
    /// crash) rather than swallowing it.
    public var encodedIdentities: [UInt8] {
        var writer = ByteWriter(reservingCapacity: 256)

        // identities<7..2^16-1>
        var identitiesData = [UInt8]()
        for identity in identities {
            do {
                identitiesData.append(contentsOf: try identity.encodeBytes())
            } catch {
                fatalError("PSK identity exceeds wire length bound: \(error)")
            }
        }
        do {
            try writer.wWriteVector16(identitiesData)
        } catch {
            fatalError("PSK identities list exceeds wire length bound: \(error)")
        }

        return writer.finishArray()
    }

    /// Size of binders section for truncation
    public var bindersSize: Int {
        // 2 bytes for binders vector length
        var size = 2
        for binder in binders {
            // 1 byte for binder length + binder data
            size += 1 + binder.count
        }
        return size
    }

    // MARK: - Decoding

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> OfferedPsks {
        var reader = ByteReader(data)

        // identities
        let identitiesData = try reader.wReadVector16()
        var identitiesReader = ByteReader(identitiesData)
        var identities: [PskIdentity] = []
        while !identitiesReader.isAtEnd {
            identities.append(try PskIdentity.decode(from: &identitiesReader))
        }

        guard !identities.isEmpty else {
            throw TLSWireError.invalidFormat("PreSharedKey: no identities")
        }

        // binders
        let bindersData = try reader.wReadVector16()
        var bindersReader = ByteReader(bindersData)
        var binders: [[UInt8]] = []
        while !bindersReader.isAtEnd {
            let binder = try bindersReader.wReadVector8()
            binders.append(binder)
        }

        guard binders.count == identities.count else {
            throw TLSWireError.invalidFormat(
                "PreSharedKey: identities count (\(identities.count)) != binders count (\(binders.count))"
            )
        }

        return OfferedPsks(identities: identities, binders: binders)
    }
}

// MARK: - Selected PSK (ServerHello)

/// PSK selected by server in ServerHello
public struct SelectedPsk: Sendable {
    /// Index of the selected PSK identity (0-based)
    public let selectedIdentity: UInt16

    public init(selectedIdentity: UInt16) {
        self.selectedIdentity = selectedIdentity
    }

    public func encodeBytes() -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 2)
        writer.writeUInt16(selectedIdentity)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> SelectedPsk {
        var reader = ByteReader(data)
        let selectedIdentity = try reader.wReadUInt16()
        return SelectedPsk(selectedIdentity: selectedIdentity)
    }
}

// MARK: - PreSharedKey Extension

/// Pre-shared key extension (for both ClientHello and ServerHello)
public enum PreSharedKeyExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .preSharedKey }

    /// ClientHello variant with offered PSKs
    case clientHello(OfferedPsks)

    /// ServerHello variant with selected PSK index
    case serverHello(SelectedPsk)

    // MARK: - Encoding

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        switch self {
        case .clientHello(let offered):
            return try offered.encodeBytes()
        case .serverHello(let selected):
            return selected.encodeBytes()
        }
    }

    // MARK: - Decoding

    /// Decode ClientHello variant
    public static func decodeClientHello(from data: [UInt8]) throws(TLSWireError) -> PreSharedKeyExtension {
        return .clientHello(try OfferedPsks.decode(from: data))
    }

    /// Decode ServerHello variant
    public static func decodeServerHello(from data: [UInt8]) throws(TLSWireError) -> PreSharedKeyExtension {
        return .serverHello(try SelectedPsk.decode(from: data))
    }
}
