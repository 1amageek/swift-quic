/// QUIC Transport Parameter codec — Embedded-clean core (RFC 9000 §18).
///
/// Encodes/decodes ``TransportParametersCore`` over `[UInt8]` via the
/// ``QUICCoreCodec`` `ByteReader`/`ByteWriter` and varint primitives. The wire
/// format is byte-for-byte identical to the historical `Data`-based
/// `TransportParameterCodec`; the `preferred_address` IPv4/IPv6 fields are
/// parsed/formatted by the host adapter via ``IPAddressCodec`` (this core only
/// moves the raw address bytes).
///
/// Embedded-clean: no Foundation, no `any`, no `inet_pton`; typed throws
/// (``TransportParameterCodecError``); no silent fallback — every malformed
/// input throws a distinct case.

import P2PCoreBytes
import QUICCoreCodec

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
    public static func encode(_ params: TransportParametersCore) -> [UInt8] {
        var writer = ByteWriter()

        // original_destination_connection_id (server only)
        if let odcid = params.originalDestinationConnectionID {
            encodeParameter(&writer, id: .originalDestinationConnectionID, data: odcid.bytes)
        }

        // max_idle_timeout
        if params.maxIdleTimeout > 0 {
            encodeVarintParameter(&writer, id: .maxIdleTimeout, value: params.maxIdleTimeout)
        }

        // stateless_reset_token (server only, 16 bytes)
        if let token = params.statelessResetToken, token.count == 16 {
            encodeParameter(&writer, id: .statelessResetToken, data: token)
        }

        // max_udp_payload_size (only if not default)
        if params.maxUDPPayloadSize != 65527 {
            encodeVarintParameter(&writer, id: .maxUDPPayloadSize, value: params.maxUDPPayloadSize)
        }

        // initial_max_data
        if params.initialMaxData > 0 {
            encodeVarintParameter(&writer, id: .initialMaxData, value: params.initialMaxData)
        }

        // initial_max_stream_data_bidi_local
        if params.initialMaxStreamDataBidiLocal > 0 {
            encodeVarintParameter(&writer, id: .initialMaxStreamDataBidiLocal,
                                  value: params.initialMaxStreamDataBidiLocal)
        }

        // initial_max_stream_data_bidi_remote
        if params.initialMaxStreamDataBidiRemote > 0 {
            encodeVarintParameter(&writer, id: .initialMaxStreamDataBidiRemote,
                                  value: params.initialMaxStreamDataBidiRemote)
        }

        // initial_max_stream_data_uni
        if params.initialMaxStreamDataUni > 0 {
            encodeVarintParameter(&writer, id: .initialMaxStreamDataUni,
                                  value: params.initialMaxStreamDataUni)
        }

        // initial_max_streams_bidi
        if params.initialMaxStreamsBidi > 0 {
            encodeVarintParameter(&writer, id: .initialMaxStreamsBidi,
                                  value: params.initialMaxStreamsBidi)
        }

        // initial_max_streams_uni
        if params.initialMaxStreamsUni > 0 {
            encodeVarintParameter(&writer, id: .initialMaxStreamsUni,
                                  value: params.initialMaxStreamsUni)
        }

        // ack_delay_exponent (only if not default 3)
        if params.ackDelayExponent != 3 {
            encodeVarintParameter(&writer, id: .ackDelayExponent, value: params.ackDelayExponent)
        }

        // max_ack_delay (only if not default 25)
        if params.maxAckDelay != 25 {
            encodeVarintParameter(&writer, id: .maxAckDelay, value: params.maxAckDelay)
        }

        // disable_active_migration (zero-length value)
        if params.disableActiveMigration {
            encodeParameter(&writer, id: .disableActiveMigration, data: [])
        }

        // preferred_address (server only)
        if let preferred = params.preferredAddress {
            encodePreferredAddress(&writer, preferred)
        }

        // active_connection_id_limit (only if not default 2)
        if params.activeConnectionIDLimit != 2 {
            encodeVarintParameter(&writer, id: .activeConnectionIDLimit,
                                  value: params.activeConnectionIDLimit)
        }

        // initial_source_connection_id
        if let iscid = params.initialSourceConnectionID {
            encodeParameter(&writer, id: .initialSourceConnectionID, data: iscid.bytes)
        }

        // retry_source_connection_id (server only, after Retry)
        if let rscid = params.retrySourceConnectionID {
            encodeParameter(&writer, id: .retrySourceConnectionID, data: rscid.bytes)
        }

        // max_datagram_frame_size (RFC 9221, only advertise when non-zero).
        // RFC 9221 §3: absence and 0 are equivalent, so we only emit when non-zero.
        if params.maxDatagramFrameSize > 0 {
            encodeVarintParameter(&writer, id: .maxDatagramFrameSize,
                                  value: params.maxDatagramFrameSize)
        }

        return writer.finishArray()
    }

    // MARK: - Decoding

    /// Decodes transport parameters from their TLS-extension byte payload.
    public static func decode(_ bytes: [UInt8]) throws(TransportParameterCodecError) -> TransportParametersCore {
        var reader = ByteReader(bytes)
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

    // MARK: - Private encoding helpers

    private static func encodeParameter(
        _ writer: inout ByteWriter,
        id: TransportParameterIDCore,
        data: [UInt8]
    ) {
        writeVarint(&writer, id.rawValue)
        writeVarint(&writer, UInt64(data.count))
        writer.writeBytes(data)
    }

    private static func encodeVarintParameter(
        _ writer: inout ByteWriter,
        id: TransportParameterIDCore,
        value: UInt64
    ) {
        let varint = Varint(value)
        writeVarint(&writer, id.rawValue)
        writeVarint(&writer, UInt64(varint.encodedLength))
        writeVarint(&writer, value)
    }

    private static func encodePreferredAddress(
        _ writer: inout ByteWriter,
        _ addr: PreferredAddressCore
    ) {
        var valueWriter = ByteWriter()

        // IPv4 address (4 bytes) + port (2 bytes)
        if let ipv4 = addr.ipv4Address, let port = addr.ipv4Port, ipv4.count == 4 {
            valueWriter.writeBytes(ipv4)
            valueWriter.writeUInt16(port)
        } else {
            // No IPv4 (or malformed) - write zeros.
            for _ in 0..<4 { valueWriter.writeByte(0) }
            valueWriter.writeUInt16(0)
        }

        // IPv6 address (16 bytes) + port (2 bytes).
        // RFC 9000 §18.2: omitting an address family is signaled by all-zero bytes and a zero
        // port. We fully serialize a present IPv6 address; absence is encoded as zeros.
        if let ipv6 = addr.ipv6Address, let port = addr.ipv6Port, ipv6.count == 16 {
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

        encodeParameter(&writer, id: .preferredAddress, data: valueWriter.finishArray())
    }

    /// Writes a QUIC varint. A `TransportParameterIDCore.rawValue` and every
    /// length/value here is within the varint range, so the write cannot fail;
    /// the typed-throws path is unwrapped with a `fatalError` only on the
    /// genuinely unreachable overflow (never a silent fallback).
    @inline(__always)
    private static func writeVarint(_ writer: inout ByteWriter, _ value: UInt64) {
        do {
            try writer.writeVarint(value)
        } catch {
            fatalError("Transport parameter varint exceeded the QUIC varint range: \(value)")
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
            params.initialMaxStreamsBidi = try decodeVarint(value)

        case .initialMaxStreamsUni:
            params.initialMaxStreamsUni = try decodeVarint(value)

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
        do {
            let (varint, _) = try Varint.decode(from: value)
            return varint.value
        } catch {
            throw .decodeError("Malformed varint in transport parameter value")
        }
    }

    private static func decodePreferredAddress(_ value: [UInt8]) throws(TransportParameterCodecError) -> PreferredAddressCore {
        var reader = ByteReader(value)

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
