/// QUIC Transport Parameter Codec (RFC 9000 Section 18)
///
/// Encodes and decodes transport parameters for the TLS handshake extension.

import Foundation
import QUICCore

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Error thrown by TransportParameterCodec
public enum TransportParameterError: Error, Sendable {
    /// Duplicate parameter ID encountered
    case duplicateParameter(UInt64)
    /// Invalid parameter value
    case invalidValue(parameter: String, reason: String)
    /// Missing required parameter
    case missingRequired(parameter: String)
    /// Insufficient data to decode
    case insufficientData
    /// Unknown error during decode
    case decodeError(String)
}

/// Codec for QUIC Transport Parameters (RFC 9000 Section 18)
public struct TransportParameterCodec: Sendable {

    /// TLS extension codepoint for QUIC transport parameters
    public static let extensionType: UInt16 = 0x0039  // 57 decimal

    /// Minimum value for max_udp_payload_size
    public static let minMaxUDPPayloadSize: UInt64 = 1200

    /// Maximum value for ack_delay_exponent
    public static let maxAckDelayExponent: UInt64 = 20

    /// Maximum value for max_ack_delay (2^14 - 1)
    public static let maxMaxAckDelay: UInt64 = (1 << 14) - 1

    /// Minimum value for active_connection_id_limit
    public static let minActiveConnectionIDLimit: UInt64 = 2

    /// Maximum value we will honor for active_connection_id_limit.
    ///
    /// RFC 9000 §18.2 does not bound this parameter, but it directly sizes the number of
    /// peer connection IDs we are willing to store. An unbounded value would let a peer flood
    /// us with NEW_CONNECTION_ID frames and exhaust memory. We therefore cap the effective
    /// limit to a small, practical maximum (a single migration rarely needs more than a
    /// handful of CIDs). This is a local resource bound on a control parameter, not an error:
    /// a peer advertising a larger willingness is simply honored up to this ceiling.
    public static let maxActiveConnectionIDLimit: UInt64 = 8

    // MARK: - Encoding

    /// Encode transport parameters for TLS extension
    /// - Parameter params: Transport parameters to encode
    /// - Returns: Encoded bytes (without TLS extension header)
    public static func encode(_ params: TransportParameters) -> Data {
        var writer = DataWriter()

        // original_destination_connection_id (server only)
        if let odcid = params.originalDestinationConnectionID {
            encodeParameter(&writer, id: .originalDestinationConnectionID, data: Data(odcid.bytes))
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
            encodeParameter(&writer, id: .disableActiveMigration, data: Data())
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
            encodeParameter(&writer, id: .initialSourceConnectionID, data: Data(iscid.bytes))
        }

        // retry_source_connection_id (server only, after Retry)
        if let rscid = params.retrySourceConnectionID {
            encodeParameter(&writer, id: .retrySourceConnectionID, data: Data(rscid.bytes))
        }

        // max_datagram_frame_size (RFC 9221, only advertise when non-zero).
        // RFC 9221 §3: absence and 0 are equivalent ("DATAGRAM frames not supported"),
        // so we only emit the parameter when we actually support DATAGRAM frames.
        if params.maxDatagramFrameSize > 0 {
            encodeVarintParameter(&writer, id: .maxDatagramFrameSize,
                                 value: params.maxDatagramFrameSize)
        }

        return writer.toData()
    }

    // MARK: - Decoding

    /// Decode transport parameters from TLS extension data
    /// - Parameter data: Encoded transport parameters
    /// - Returns: Decoded TransportParameters
    /// - Throws: `TransportParameterError` on decode failure
    public static func decode(_ data: Data) throws -> TransportParameters {
        var reader = DataReader(data)
        var params = TransportParameters()
        var seenIDs = Set<UInt64>()

        while reader.hasRemaining {
            let id = try reader.readVarintValue()
            let length = try reader.readVarintValue()

            // Check for duplicate parameters (protocol violation)
            guard !seenIDs.contains(id) else {
                throw TransportParameterError.duplicateParameter(id)
            }
            seenIDs.insert(id)

            let safeLength = try SafeConversions.toInt(
                length,
                maxAllowed: ProtocolLimits.maxTransportParameterLength,
                context: "Transport parameter value length"
            )
            guard let value = reader.readBytes(safeLength) else {
                throw TransportParameterError.insufficientData
            }

            try decodeParameter(&params, id: id, value: value)
        }

        return params
    }

    // MARK: - Private Encoding Helpers

    private static func encodeParameter(
        _ writer: inout DataWriter,
        id: TransportParameterID,
        data: Data
    ) {
        writer.writeVarint(id.rawValue)
        writer.writeVarint(UInt64(data.count))
        writer.writeBytes(data)
    }

    private static func encodeVarintParameter(
        _ writer: inout DataWriter,
        id: TransportParameterID,
        value: UInt64
    ) {
        let varint = Varint(value)
        writer.writeVarint(id.rawValue)
        writer.writeVarint(UInt64(varint.encodedLength))
        writer.writeVarint(varint)
    }

    private static func encodePreferredAddress(
        _ writer: inout DataWriter,
        _ addr: PreferredAddress
    ) {
        var valueWriter = DataWriter()

        // IPv4 address (4 bytes) + port (2 bytes)
        if let ipv4 = addr.ipv4Address, let port = addr.ipv4Port {
            let components = ipv4.split(separator: ".").compactMap { UInt8($0) }
            if components.count == 4 {
                for byte in components {
                    valueWriter.writeByte(byte)
                }
            } else {
                // Invalid IPv4 - write zeros
                for _ in 0..<4 { valueWriter.writeByte(0) }
            }
            valueWriter.writeUInt16(port)
        } else {
            // No IPv4 - write zeros
            for _ in 0..<4 { valueWriter.writeByte(0) }
            valueWriter.writeUInt16(0)
        }

        // IPv6 address (16 bytes) + port (2 bytes).
        // RFC 9000 §18.2: omitting an address family is signaled by all-zero bytes and a zero
        // port. We fully serialize a present IPv6 address; absence is encoded as zeros.
        if let ipv6 = addr.ipv6Address, let port = addr.ipv6Port,
           let bytes = Self.parseIPv6(ipv6) {
            valueWriter.writeBytes(Data(bytes))
            valueWriter.writeUInt16(port)
        } else {
            // A non-parseable IPv6 string is a caller error (PreferredAddress should hold a
            // valid address). Flag it in debug; we never emit a partial/garbage address.
            assert(addr.ipv6Address == nil, "PreferredAddress.ipv6Address must be a valid IPv6 literal")
            for _ in 0..<16 { valueWriter.writeByte(0) }
            valueWriter.writeUInt16(0)
        }

        // Connection ID length (1 byte) + Connection ID
        valueWriter.writeByte(UInt8(addr.connectionID.length))
        valueWriter.writeBytes(addr.connectionID.bytes)

        // Stateless Reset Token (16 bytes)
        valueWriter.writeBytes(addr.statelessResetToken)

        encodeParameter(&writer, id: .preferredAddress, data: valueWriter.toData())
    }

    // MARK: - Private Decoding Helpers

    private static func decodeParameter(
        _ params: inout TransportParameters,
        id: UInt64,
        value: Data
    ) throws {
        guard let paramID = TransportParameterID(rawValue: id) else {
            // Unknown parameter - ignore per RFC 9000 Section 18.1
            // GREASE values (27742 * N + 31) are also ignored
            return
        }

        switch paramID {
        case .originalDestinationConnectionID:
            params.originalDestinationConnectionID = try ConnectionID(bytes: value)

        case .maxIdleTimeout:
            params.maxIdleTimeout = try decodeVarint(value)

        case .statelessResetToken:
            guard value.count == 16 else {
                throw TransportParameterError.invalidValue(
                    parameter: "stateless_reset_token",
                    reason: "Must be exactly 16 bytes, got \(value.count)"
                )
            }
            params.statelessResetToken = value

        case .maxUDPPayloadSize:
            let size = try decodeVarint(value)
            guard size >= minMaxUDPPayloadSize else {
                throw TransportParameterError.invalidValue(
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
                throw TransportParameterError.invalidValue(
                    parameter: "ack_delay_exponent",
                    reason: "Must be <= \(maxAckDelayExponent), got \(exp)"
                )
            }
            params.ackDelayExponent = exp

        case .maxAckDelay:
            let delay = try decodeVarint(value)
            guard delay <= maxMaxAckDelay else {
                throw TransportParameterError.invalidValue(
                    parameter: "max_ack_delay",
                    reason: "Must be <= \(maxMaxAckDelay), got \(delay)"
                )
            }
            params.maxAckDelay = delay

        case .disableActiveMigration:
            guard value.isEmpty else {
                throw TransportParameterError.invalidValue(
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
                throw TransportParameterError.invalidValue(
                    parameter: "active_connection_id_limit",
                    reason: "Must be >= \(minActiveConnectionIDLimit), got \(limit)"
                )
            }
            // Cap the effective limit to bound peer-CID storage (see maxActiveConnectionIDLimit).
            // A value beyond the ceiling is honored up to the ceiling rather than rejected,
            // because this parameter is a resource control rather than a correctness invariant.
            params.activeConnectionIDLimit = min(limit, maxActiveConnectionIDLimit)

        case .initialSourceConnectionID:
            params.initialSourceConnectionID = try ConnectionID(bytes: value)

        case .retrySourceConnectionID:
            params.retrySourceConnectionID = try ConnectionID(bytes: value)

        case .maxDatagramFrameSize:
            params.maxDatagramFrameSize = try decodeVarint(value)
        }
    }

    private static func decodeVarint(_ data: Data) throws -> UInt64 {
        let (varint, _) = try Varint.decode(from: data)
        return varint.value
    }

    private static func decodePreferredAddress(_ data: Data) throws -> PreferredAddress {
        var reader = DataReader(data)

        // IPv4: 4 bytes address + 2 bytes port
        guard let ipv4Bytes = reader.readBytes(4),
              let ipv4Port = reader.readUInt16() else {
            throw TransportParameterError.decodeError("Invalid preferred address IPv4")
        }

        // IPv6: 16 bytes address + 2 bytes port
        guard let ipv6Bytes = reader.readBytes(16),
              let ipv6PortValue = reader.readUInt16() else {
            throw TransportParameterError.decodeError("Invalid preferred address IPv6")
        }

        // Connection ID
        guard let cidLen = reader.readByte() else {
            throw TransportParameterError.decodeError("Invalid preferred address CID length")
        }
        guard cidLen <= ConnectionID.maxLength else {
            throw TransportParameterError.decodeError(
                "Preferred address CID too long: \(cidLen) > \(ConnectionID.maxLength)"
            )
        }
        guard let cidBytes = reader.readBytes(Int(cidLen)) else {
            throw TransportParameterError.decodeError("Invalid preferred address CID")
        }

        // Stateless Reset Token
        guard let resetToken = reader.readBytes(ProtocolLimits.statelessResetTokenLength) else {
            throw TransportParameterError.decodeError("Invalid preferred address reset token")
        }

        // RFC 9000 §18.2: an address family that is not offered is encoded as all-zero address
        // bytes and a zero port. Decode an all-zero family as "absent" (nil) rather than as the
        // wildcard literal, which would be an unusable migration target.
        let ipv4AllZero = ipv4Bytes.allSatisfy { $0 == 0 } && ipv4Port == 0
        let ipv4Address = ipv4AllZero ? nil : ipv4Bytes.map { String($0) }.joined(separator: ".")
        let ipv4PortDecoded: UInt16? = ipv4AllZero ? nil : ipv4Port

        let ipv6AllZero = ipv6Bytes.allSatisfy { $0 == 0 } && ipv6PortValue == 0
        let ipv6Address: String?
        let ipv6PortDecoded: UInt16?
        if ipv6AllZero {
            ipv6Address = nil
            ipv6PortDecoded = nil
        } else {
            // Fully parse the 16-byte IPv6 address into its canonical textual form so the
            // migration target is actually usable (no silent zero/discard).
            guard let formatted = Self.formatIPv6([UInt8](ipv6Bytes)) else {
                throw TransportParameterError.decodeError("Invalid preferred address IPv6 bytes")
            }
            ipv6Address = formatted
            ipv6PortDecoded = ipv6PortValue
        }

        return PreferredAddress(
            ipv4Address: ipv4Address,
            ipv4Port: ipv4PortDecoded,
            ipv6Address: ipv6Address,
            ipv6Port: ipv6PortDecoded,
            connectionID: try ConnectionID(bytes: cidBytes),
            statelessResetToken: resetToken
        )
    }

    // MARK: - IPv6 Address Helpers

    /// Parses an IPv6 textual address into its 16-byte network representation.
    /// - Returns: 16 bytes, or `nil` if the string is not a valid IPv6 literal.
    static func parseIPv6(_ string: String) -> [UInt8]? {
        var addr = in6_addr()
        let result = string.withCString { cString in
            inet_pton(AF_INET6, cString, &addr)
        }
        guard result == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    /// Formats a 16-byte IPv6 network representation into its canonical textual form.
    /// - Returns: The textual address, or `nil` if the byte count is wrong or formatting fails.
    static func formatIPv6(_ bytes: [UInt8]) -> String? {
        guard bytes.count == 16 else { return nil }
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { raw in
            bytes.withUnsafeBytes { src in
                raw.copyMemory(from: src)
            }
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
        guard result != nil else { return nil }
        return String(cString: buffer)
    }
}
