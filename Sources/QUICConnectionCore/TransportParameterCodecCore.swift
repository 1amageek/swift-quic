/// QUIC Transport Parameter codec — Embedded-clean core (RFC 9000 §18).
///
/// Encodes/decodes ``TransportParametersCore`` over `[UInt8]` via the
/// ``QUICWire`` `QUICWireReader`/`QUICWireWriter` and varint primitives.
/// `preferred_address` IPv4/IPv6 fields remain raw network-order bytes; textual
/// conversion is available separately through ``IPAddressCodec``.
///
/// Embedded-clean: no Foundation, no `any`, no `inet_pton`; typed throws
/// (``TransportParameterCodecError``); no silent fallback — every malformed
/// input throws a distinct case.

import NetworkingCore
import QUICWire

/// Error thrown by ``TransportParameterCodecCore``.
public enum TransportParameterCodecError: Error, Sendable, Equatable {
    /// Duplicate parameter ID encountered (protocol violation).
    case duplicateParameter(UInt64)
    /// A parameter value failed its RFC 9000 §18.2 validity check.
    case invalidValue(parameter: String, reason: String)
    /// Insufficient data to decode a parameter.
    case insufficientData
    /// A structural decode error (malformed preferred_address, bad varint, …).
    case decodeError(String)
    /// A local value cannot be represented on the QUIC transport-parameter wire.
    case encodeError(String)
}

/// Codec for QUIC Transport Parameters (RFC 9000 §18), Embedded-clean.
public enum TransportParameterCodecCore {

    // MARK: - Validation constants

    /// Minimum value for max_udp_payload_size.
    public static let minMaxUDPPayloadSize: UInt64 = 1200

    /// Maximum value for ack_delay_exponent.
    public static let maxAckDelayExponent: UInt64 = 20

    /// Maximum value for max_ack_delay (2^14 - 1).
    public static let maxMaxAckDelay: UInt64 = (1 << 14) - 1

    /// Minimum value for active_connection_id_limit.
    public static let minActiveConnectionIDLimit: UInt64 = 2

    /// Maximum stream count representable by a valid MAX_STREAMS frame.
    public static let maxInitialStreams: UInt64 = ProtocolLimits.maxStreams

    /// Maximum value we will honor for active_connection_id_limit.
    ///
    /// RFC 9000 §18.2 does not bound this parameter, but it directly sizes the number of
    /// peer connection IDs we are willing to store. An unbounded value would let a peer flood
    /// us with NEW_CONNECTION_ID frames and exhaust memory. We therefore cap the effective
    /// limit to a small, practical maximum.
    public static let maxActiveConnectionIDLimit: UInt64 = 8

    // MARK: - Encoding

    /// Encodes transport parameters to their TLS-extension byte payload
    /// (without the TLS extension header).
    public static func encode(
        _ params: TransportParametersCore
    ) throws(TransportParameterCodecError) -> [UInt8] {
        try validateForEncoding(params)
        var writer = QUICWireWriter()

        // original_destination_connection_id (server only)
        if let odcid = params.originalDestinationConnectionID {
            try encodeParameter(&writer, id: .originalDestinationConnectionID, data: odcid.bytes)
        }

        // max_idle_timeout
        if params.maxIdleTimeout > 0 {
            try encodeVarintParameter(&writer, id: .maxIdleTimeout, value: params.maxIdleTimeout)
        }

        // stateless_reset_token (server only, 16 bytes)
        if let token = params.statelessResetToken {
            try encodeParameter(&writer, id: .statelessResetToken, data: token)
        }

        // max_udp_payload_size (only if not default)
        if params.maxUDPPayloadSize != 65527 {
            try encodeVarintParameter(&writer, id: .maxUDPPayloadSize, value: params.maxUDPPayloadSize)
        }

        // initial_max_data
        if params.initialMaxData > 0 {
            try encodeVarintParameter(&writer, id: .initialMaxData, value: params.initialMaxData)
        }

        // initial_max_stream_data_bidi_local
        if params.initialMaxStreamDataBidiLocal > 0 {
            try encodeVarintParameter(&writer, id: .initialMaxStreamDataBidiLocal,
                                  value: params.initialMaxStreamDataBidiLocal)
        }

        // initial_max_stream_data_bidi_remote
        if params.initialMaxStreamDataBidiRemote > 0 {
            try encodeVarintParameter(&writer, id: .initialMaxStreamDataBidiRemote,
                                  value: params.initialMaxStreamDataBidiRemote)
        }

        // initial_max_stream_data_uni
        if params.initialMaxStreamDataUni > 0 {
            try encodeVarintParameter(&writer, id: .initialMaxStreamDataUni,
                                  value: params.initialMaxStreamDataUni)
        }

        // initial_max_streams_bidi
        if params.initialMaxStreamsBidi > 0 {
            try encodeVarintParameter(&writer, id: .initialMaxStreamsBidi,
                                  value: params.initialMaxStreamsBidi)
        }

        // initial_max_streams_uni
        if params.initialMaxStreamsUni > 0 {
            try encodeVarintParameter(&writer, id: .initialMaxStreamsUni,
                                  value: params.initialMaxStreamsUni)
        }

        // ack_delay_exponent (only if not default 3)
        if params.ackDelayExponent != 3 {
            try encodeVarintParameter(&writer, id: .ackDelayExponent, value: params.ackDelayExponent)
        }

        // max_ack_delay (only if not default 25)
        if params.maxAckDelay != 25 {
            try encodeVarintParameter(&writer, id: .maxAckDelay, value: params.maxAckDelay)
        }

        // disable_active_migration (zero-length value)
        if params.disableActiveMigration {
            try encodeParameter(&writer, id: .disableActiveMigration, data: [])
        }

        // preferred_address (server only)
        if let preferred = params.preferredAddress {
            try encodePreferredAddress(&writer, preferred)
        }

        // active_connection_id_limit (only if not default 2)
        if params.activeConnectionIDLimit != 2 {
            try encodeVarintParameter(&writer, id: .activeConnectionIDLimit,
                                  value: params.activeConnectionIDLimit)
        }

        // initial_source_connection_id
        if let iscid = params.initialSourceConnectionID {
            try encodeParameter(&writer, id: .initialSourceConnectionID, data: iscid.bytes)
        }

        // retry_source_connection_id (server only, after Retry)
        if let rscid = params.retrySourceConnectionID {
            try encodeParameter(&writer, id: .retrySourceConnectionID, data: rscid.bytes)
        }

        // reset_stream_at (draft-ietf-quic-reliable-stream-reset-09) and the
        // draft-07 provisional identifier used by quic-go 0.60. Advertising
        // both preserves the canonical capability while enabling current Go
        // peers to negotiate partial-delivery reset in both directions.
        if params.enableResetStreamAt {
            try encodeParameter(&writer, id: .resetStreamAt, data: [])
            try encodeParameter(&writer, id: .resetStreamAtDraft07, data: [])
        }

        // max_datagram_frame_size (RFC 9221, only advertise when non-zero).
        // RFC 9221 §3: absence and 0 are equivalent, so we only emit when non-zero.
        if params.maxDatagramFrameSize > 0 {
            try encodeVarintParameter(&writer, id: .maxDatagramFrameSize,
                                  value: params.maxDatagramFrameSize)
        }

        return writer.finishArray()
    }

    // MARK: - Decoding

    /// Decodes transport parameters from their TLS-extension byte payload.
    public static func decode(
        _ bytes: Span<UInt8>
    ) throws(TransportParameterCodecError) -> TransportParametersCore {
        var reader = QUICWireReader(bytes)
        var params = TransportParametersCore()
        var seenIDs = Set<UInt64>()

        while !reader.isAtEnd {
            let id: UInt64
            let length: UInt64
            do {
                id = try reader.readVarint()
                length = try reader.readVarint()
            } catch {
                throw .insufficientData
            }

            // Reject duplicate parameters (protocol violation).
            guard !seenIDs.contains(id) else {
                throw .duplicateParameter(id)
            }
            seenIDs.insert(id)

            let safeLength: Int
            do {
                safeLength = try SafeConversions.toInt(
                    length,
                    maxAllowed: ProtocolLimits.maxTransportParameterLength,
                    context: "Transport parameter value length"
                )
            } catch {
                throw .insufficientData
            }

            let value: [UInt8]
            do {
                value = try reader.readBytes(safeLength)
            } catch {
                throw .insufficientData
            }

            try decodeParameter(&params, id: id, value: value)
        }

        return params
    }

    public static func decode(
        _ bytes: borrowing [UInt8]
    ) throws(TransportParameterCodecError) -> TransportParametersCore {
        try decode(bytes.span)
    }

    // MARK: - Private encoding helpers

    private static func encodeParameter(
        _ writer: inout QUICWireWriter,
        id: TransportParameterIDCore,
        data: [UInt8]
    ) throws(TransportParameterCodecError) {
        try writeVarint(&writer, id.rawValue)
        try writeVarint(&writer, UInt64(data.count))
        writer.writeBytes(data)
    }

    private static func encodeVarintParameter(
        _ writer: inout QUICWireWriter,
        id: TransportParameterIDCore,
        value: UInt64
    ) throws(TransportParameterCodecError) {
        let encodedLength = Varint.encodedLength(for: value)
        try writeVarint(&writer, id.rawValue)
        try writeVarint(&writer, UInt64(encodedLength))
        try writeVarint(&writer, value)
    }

    private static func encodePreferredAddress(
        _ writer: inout QUICWireWriter,
        _ addr: PreferredAddressCore
    ) throws(TransportParameterCodecError) {
        var valueWriter = QUICWireWriter()

        // IPv4 address (4 bytes) + port (2 bytes)
        if let ipv4 = addr.ipv4Address, let port = addr.ipv4Port {
            valueWriter.writeBytes(ipv4)
            valueWriter.writeUInt16(port)
        } else {
            // No IPv4 is represented by an all-zero address and port.
            for _ in 0..<4 { valueWriter.writeByte(0) }
            valueWriter.writeUInt16(0)
        }

        // IPv6 address (16 bytes) + port (2 bytes).
        // RFC 9000 §18.2: omitting an address family is signaled by all-zero bytes and a zero
        // port. We fully serialize a present IPv6 address; absence is encoded as zeros.
        if let ipv6 = addr.ipv6Address, let port = addr.ipv6Port {
            valueWriter.writeBytes(ipv6)
            valueWriter.writeUInt16(port)
        } else {
            for _ in 0..<16 { valueWriter.writeByte(0) }
            valueWriter.writeUInt16(0)
        }

        // Connection ID length (1 byte) + Connection ID
        valueWriter.writeByte(UInt8(addr.connectionID.length))
        valueWriter.writeBytes(addr.connectionID.bytes)

        // Stateless Reset Token (16 bytes)
        valueWriter.writeBytes(addr.statelessResetToken)

        try encodeParameter(&writer, id: .preferredAddress, data: valueWriter.finishArray())
    }

    /// Validates local values before any bytes are emitted. Invalid optional
    /// fields must not be silently omitted or rewritten as absent values.
    private static func validateForEncoding(
        _ params: TransportParametersCore
    ) throws(TransportParameterCodecError) {
        guard params.maxUDPPayloadSize >= minMaxUDPPayloadSize else {
            throw .invalidValue(
                parameter: "max_udp_payload_size",
                reason: "Must be >= \(minMaxUDPPayloadSize), got \(params.maxUDPPayloadSize)"
            )
        }
        guard params.ackDelayExponent <= maxAckDelayExponent else {
            throw .invalidValue(
                parameter: "ack_delay_exponent",
                reason: "Must be <= \(maxAckDelayExponent), got \(params.ackDelayExponent)"
            )
        }
        guard params.maxAckDelay <= maxMaxAckDelay else {
            throw .invalidValue(
                parameter: "max_ack_delay",
                reason: "Must be <= \(maxMaxAckDelay), got \(params.maxAckDelay)"
            )
        }
        guard params.activeConnectionIDLimit >= minActiveConnectionIDLimit else {
            throw .invalidValue(
                parameter: "active_connection_id_limit",
                reason: "Must be >= \(minActiveConnectionIDLimit), got \(params.activeConnectionIDLimit)"
            )
        }
        guard params.initialMaxStreamsBidi <= maxInitialStreams else {
            throw .invalidValue(
                parameter: "initial_max_streams_bidi",
                reason: "Must be <= \(maxInitialStreams), got \(params.initialMaxStreamsBidi)"
            )
        }
        guard params.initialMaxStreamsUni <= maxInitialStreams else {
            throw .invalidValue(
                parameter: "initial_max_streams_uni",
                reason: "Must be <= \(maxInitialStreams), got \(params.initialMaxStreamsUni)"
            )
        }
        if let token = params.statelessResetToken {
            guard token.count == ProtocolLimits.statelessResetTokenLength else {
                throw .invalidValue(
                    parameter: "stateless_reset_token",
                    reason: "Must be exactly \(ProtocolLimits.statelessResetTokenLength) bytes, got \(token.count)"
                )
            }
        }
        if let preferred = params.preferredAddress {
            try validatePreferredAddressForEncoding(preferred)
        }
    }

    private static func validatePreferredAddressForEncoding(
        _ address: PreferredAddressCore
    ) throws(TransportParameterCodecError) {
        switch (address.ipv4Address, address.ipv4Port) {
        case (nil, nil):
            break
        case (.some(let bytes), .some):
            guard bytes.count == 4 else {
                throw .invalidValue(
                    parameter: "preferred_address.ipv4",
                    reason: "Must be exactly 4 bytes, got \(bytes.count)"
                )
            }
        default:
            throw .invalidValue(
                parameter: "preferred_address.ipv4",
                reason: "Address and port must either both be present or both be absent"
            )
        }

        switch (address.ipv6Address, address.ipv6Port) {
        case (nil, nil):
            break
        case (.some(let bytes), .some):
            guard bytes.count == 16 else {
                throw .invalidValue(
                    parameter: "preferred_address.ipv6",
                    reason: "Must be exactly 16 bytes, got \(bytes.count)"
                )
            }
        default:
            throw .invalidValue(
                parameter: "preferred_address.ipv6",
                reason: "Address and port must either both be present or both be absent"
            )
        }

        guard address.statelessResetToken.count == ProtocolLimits.statelessResetTokenLength else {
            throw .invalidValue(
                parameter: "preferred_address.stateless_reset_token",
                reason: "Must be exactly \(ProtocolLimits.statelessResetTokenLength) bytes, got \(address.statelessResetToken.count)"
            )
        }
    }

    @inline(__always)
    private static func writeVarint(
        _ writer: inout QUICWireWriter,
        _ value: UInt64
    ) throws(TransportParameterCodecError) {
        do {
            try writer.writeVarint(value)
        } catch {
            throw .encodeError("value exceeds the QUIC varint range")
        }
    }

    // MARK: - Private decoding helpers

    private static func decodeParameter(
        _ params: inout TransportParametersCore,
        id: UInt64,
        value: [UInt8]
    ) throws(TransportParameterCodecError) {
        guard let paramID = TransportParameterIDCore(rawValue: id) else {
            // Unknown parameter - ignore per RFC 9000 §18.1. GREASE values too.
            return
        }

        switch paramID {
        case .originalDestinationConnectionID:
            params.originalDestinationConnectionID = try connectionID(value)

        case .maxIdleTimeout:
            params.maxIdleTimeout = try decodeVarint(value)

        case .statelessResetToken:
            guard value.count == 16 else {
                throw .invalidValue(
                    parameter: "stateless_reset_token",
                    reason: "Must be exactly 16 bytes, got \(value.count)"
                )
            }
            params.statelessResetToken = value

        case .maxUDPPayloadSize:
            let size = try decodeVarint(value)
            guard size >= minMaxUDPPayloadSize else {
                throw .invalidValue(
                    parameter: "max_udp_payload_size",
                    reason: "Must be >= \(minMaxUDPPayloadSize), got \(size)"
                )
            }
            params.maxUDPPayloadSize = size

        case .initialMaxData:
            params.initialMaxData = try decodeVarint(value)

        case .initialMaxStreamDataBidiLocal:
            params.initialMaxStreamDataBidiLocal = try decodeVarint(value)

        case .initialMaxStreamDataBidiRemote:
            params.initialMaxStreamDataBidiRemote = try decodeVarint(value)

        case .initialMaxStreamDataUni:
            params.initialMaxStreamDataUni = try decodeVarint(value)

        case .initialMaxStreamsBidi:
            let count = try decodeVarint(value)
            guard count <= maxInitialStreams else {
                throw .invalidValue(
                    parameter: "initial_max_streams_bidi",
                    reason: "Must be <= \(maxInitialStreams), got \(count)"
                )
            }
            params.initialMaxStreamsBidi = count

        case .initialMaxStreamsUni:
            let count = try decodeVarint(value)
            guard count <= maxInitialStreams else {
                throw .invalidValue(
                    parameter: "initial_max_streams_uni",
                    reason: "Must be <= \(maxInitialStreams), got \(count)"
                )
            }
            params.initialMaxStreamsUni = count

        case .ackDelayExponent:
            let exp = try decodeVarint(value)
            guard exp <= maxAckDelayExponent else {
                throw .invalidValue(
                    parameter: "ack_delay_exponent",
                    reason: "Must be <= \(maxAckDelayExponent), got \(exp)"
                )
            }
            params.ackDelayExponent = exp

        case .maxAckDelay:
            let delay = try decodeVarint(value)
            guard delay <= maxMaxAckDelay else {
                throw .invalidValue(
                    parameter: "max_ack_delay",
                    reason: "Must be <= \(maxMaxAckDelay), got \(delay)"
                )
            }
            params.maxAckDelay = delay

        case .disableActiveMigration:
            guard value.isEmpty else {
                throw .invalidValue(
                    parameter: "disable_active_migration",
                    reason: "Must be empty (zero-length)"
                )
            }
            params.disableActiveMigration = true

        case .preferredAddress:
            params.preferredAddress = try decodePreferredAddress(value)

        case .activeConnectionIDLimit:
            let limit = try decodeVarint(value)
            guard limit >= minActiveConnectionIDLimit else {
                throw .invalidValue(
                    parameter: "active_connection_id_limit",
                    reason: "Must be >= \(minActiveConnectionIDLimit), got \(limit)"
                )
            }
            // Cap the effective limit to bound peer-CID storage (see maxActiveConnectionIDLimit).
            params.activeConnectionIDLimit = min(limit, maxActiveConnectionIDLimit)

        case .initialSourceConnectionID:
            params.initialSourceConnectionID = try connectionID(value)

        case .retrySourceConnectionID:
            params.retrySourceConnectionID = try connectionID(value)

        case .resetStreamAt, .resetStreamAtDraft07:
            guard value.isEmpty else {
                throw .invalidValue(
                    parameter: "reset_stream_at",
                    reason: "Must be empty (zero-length)"
                )
            }
            params.enableResetStreamAt = true

        case .maxDatagramFrameSize:
            params.maxDatagramFrameSize = try decodeVarint(value)
        }
    }

    /// Builds a ``ConnectionID`` from a parameter value, mapping the typed CID
    /// error onto our codec error (never a silent truncation).
    private static func connectionID(_ value: [UInt8]) throws(TransportParameterCodecError) -> ConnectionID {
        do {
            return try ConnectionID(bytes: value)
        } catch {
            throw .decodeError("Connection ID exceeds \(ConnectionID.maxLength) bytes")
        }
    }

    private static func decodeVarint(_ value: [UInt8]) throws(TransportParameterCodecError) -> UInt64 {
        let decoded: (varint: Varint, consumed: Int)
        do {
            decoded = try Varint.decode(from: value)
        } catch {
            throw .decodeError("Malformed varint in transport parameter value")
        }
        guard decoded.consumed == value.count else {
            throw .decodeError("Trailing bytes after transport parameter varint")
        }
        return decoded.varint.value
    }

    private static func decodePreferredAddress(_ value: [UInt8]) throws(TransportParameterCodecError) -> PreferredAddressCore {
        var reader = QUICWireReader(value)

        // IPv4: 4 bytes address + 2 bytes port
        let ipv4Bytes: [UInt8]
        let ipv4PortValue: UInt16
        do {
            ipv4Bytes = try reader.readBytes(4)
            ipv4PortValue = try reader.readUInt16()
        } catch {
            throw .decodeError("Invalid preferred address IPv4")
        }

        // IPv6: 16 bytes address + 2 bytes port
        let ipv6Bytes: [UInt8]
        let ipv6PortValue: UInt16
        do {
            ipv6Bytes = try reader.readBytes(16)
            ipv6PortValue = try reader.readUInt16()
        } catch {
            throw .decodeError("Invalid preferred address IPv6")
        }

        // Connection ID length (1 byte) + Connection ID
        let cidLen: UInt8
        do {
            cidLen = try reader.readUInt8()
        } catch {
            throw .decodeError("Invalid preferred address CID length")
        }
        guard UInt64(cidLen) <= UInt64(ConnectionID.maxLength) else {
            throw .decodeError("Preferred address CID too long: \(cidLen) > \(ConnectionID.maxLength)")
        }
        let cidBytes: [UInt8]
        do {
            cidBytes = try reader.readBytes(Int(cidLen))
        } catch {
            throw .decodeError("Invalid preferred address CID")
        }

        // Stateless Reset Token (16 bytes)
        let resetToken: [UInt8]
        do {
            resetToken = try reader.readBytes(ProtocolLimits.statelessResetTokenLength)
        } catch {
            throw .decodeError("Invalid preferred address reset token")
        }
        guard reader.isAtEnd else {
            throw .decodeError("Trailing bytes after preferred address")
        }

        // RFC 9000 §18.2: an address family that is not offered is encoded as all-zero address
        // bytes and a zero port. Decode an all-zero family as "absent" (nil).
        let ipv4AllZero = ipv4Bytes.allSatisfy { $0 == 0 } && ipv4PortValue == 0
        let ipv4Address: [UInt8]? = ipv4AllZero ? nil : ipv4Bytes
        let ipv4Port: UInt16? = ipv4AllZero ? nil : ipv4PortValue

        let ipv6AllZero = ipv6Bytes.allSatisfy { $0 == 0 } && ipv6PortValue == 0
        let ipv6Address: [UInt8]? = ipv6AllZero ? nil : ipv6Bytes
        let ipv6Port: UInt16? = ipv6AllZero ? nil : ipv6PortValue

        return PreferredAddressCore(
            ipv4Address: ipv4Address,
            ipv4Port: ipv4Port,
            ipv6Address: ipv6Address,
            ipv6Port: ipv6Port,
            connectionID: try connectionID(cidBytes),
            statelessResetToken: resetToken
        )
    }
}
