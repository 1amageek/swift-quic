/// TLS 1.3 NewSessionTicket Message (RFC 8446 Section 4.6.1)
///
/// ```
/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
/// ```
///
/// The server sends this message after the handshake to establish
/// a PSK that can be used for session resumption.
///
/// The crypto/Date-bearing `SessionTicketData` (which holds the resumption PSK
/// and the receive `Date`) lives in the `QUICCrypto` adapter; this core file
/// carries only the pure wire types.

import P2PCoreBytes

// MARK: - NewSessionTicket Message

/// TLS 1.3 NewSessionTicket message for session resumption
public struct NewSessionTicket: Sendable {
    /// Ticket lifetime in seconds (max: 604800 = 7 days)
    public let ticketLifetime: UInt32

    /// Random value added to ticket age to obscure real age
    public let ticketAgeAdd: UInt32

    /// Per-ticket nonce for PSK derivation
    public let ticketNonce: [UInt8]

    /// The ticket value (opaque to client)
    public let ticket: [UInt8]

    /// Extensions (e.g., early_data max size)
    public let extensions: [TLSExtension]

    /// Maximum ticket lifetime (7 days)
    public static let maxLifetime: UInt32 = 604800

    // MARK: - Initialization

    public init(
        ticketLifetime: UInt32,
        ticketAgeAdd: UInt32,
        ticketNonce: [UInt8],
        ticket: [UInt8],
        extensions: [TLSExtension] = []
    ) {
        self.ticketLifetime = min(ticketLifetime, Self.maxLifetime)
        self.ticketAgeAdd = ticketAgeAdd
        self.ticketNonce = ticketNonce
        self.ticket = ticket
        self.extensions = extensions
    }

    // MARK: - Encoding

    /// Encode the message content (without handshake header)
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 256)

        // ticket_lifetime (4 bytes)
        writer.writeUInt32(ticketLifetime)

        // ticket_age_add (4 bytes)
        writer.writeUInt32(ticketAgeAdd)

        // ticket_nonce<0..255>
        try writer.wWriteVector8(ticketNonce)

        // ticket<1..2^16-1>
        try writer.wWriteVector16(ticket)

        // extensions<0..2^16-2>
        var extensionsData = [UInt8]()
        for ext in extensions {
            extensionsData.append(contentsOf: try ext.encodeBytes())
        }
        try writer.wWriteVector16(extensionsData)

        return writer.finishArray()
    }

    /// Encode as complete handshake message
    public func encodeMessageBytes() throws(TLSWireError) -> [UInt8] {
        let content = try encodeBytes()
        return try HandshakeMessageCodec.encode(type: .newSessionTicket, content: content)
    }

    // MARK: - Decoding

    /// Decode from message content (without handshake header)
    public static func decode(from data: [UInt8]) throws(TLSWireError) -> NewSessionTicket {
        var reader = ByteReader(data)

        // ticket_lifetime
        let ticketLifetime = try reader.wReadUInt32()

        // ticket_age_add
        let ticketAgeAdd = try reader.wReadUInt32()

        // ticket_nonce
        let ticketNonce = try reader.wReadVector8()

        // ticket
        let ticket = try reader.wReadVector16()
        guard !ticket.isEmpty else {
            throw TLSWireError.invalidFormat("NewSessionTicket: ticket must not be empty")
        }

        // extensions (use NewSessionTicket-specific decoding for early_data)
        var extensions: [TLSExtension] = []
        let extensionsData = try reader.wReadVector16()
        if !extensionsData.isEmpty {
            var extReader = ByteReader(extensionsData)
            while !extReader.isAtEnd {
                let ext = try TLSExtension.decodeForNewSessionTicket(from: &extReader)
                extensions.append(ext)
            }
        }

        return NewSessionTicket(
            ticketLifetime: ticketLifetime,
            ticketAgeAdd: ticketAgeAdd,
            ticketNonce: ticketNonce,
            ticket: ticket,
            extensions: extensions
        )
    }
}

// MARK: - Early Data Extension in NewSessionTicket

/// Early data indication extension (RFC 8446 Section 4.2.10)
/// When present in NewSessionTicket, contains max_early_data_size.
public struct EarlyDataIndication: Sendable {
    /// Maximum size of early data (in bytes)
    /// Only present in NewSessionTicket, not in ClientHello/EncryptedExtensions
    public let maxEarlyDataSize: UInt32?

    public init(maxEarlyDataSize: UInt32? = nil) {
        self.maxEarlyDataSize = maxEarlyDataSize
    }

    public func encodeBytes() -> [UInt8] {
        if let size = maxEarlyDataSize {
            var writer = ByteWriter(reservingCapacity: 4)
            writer.writeUInt32(size)
            return writer.finishArray()
        } else {
            return []
        }
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> EarlyDataIndication {
        if data.isEmpty {
            return EarlyDataIndication(maxEarlyDataSize: nil)
        }

        var reader = ByteReader(data)
        let size = try reader.wReadUInt32()
        return EarlyDataIndication(maxEarlyDataSize: size)
    }
}
