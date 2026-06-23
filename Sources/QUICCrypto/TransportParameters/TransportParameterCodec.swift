/// QUIC Transport Parameter Codec (RFC 9000 Section 18) — host adapter.
///
/// This is the Foundation-facing adapter over the Embedded-clean
/// ``TransportParameterCodecCore``. It keeps the historical `Data`-based
/// `encode(_:) -> Data` / `decode(_:) throws -> TransportParameters` surface and
/// the `parseIPv6`/`formatIPv6` helpers that existing call sites and tests use,
/// bridging at the boundary:
/// - `TransportParameters` (String IPv6, `Data` token) <-> `TransportParametersCore`
///   (`[UInt8]` IPv6, `[UInt8]` token), via ``IPAddressCodec`` for the
///   preferred_address IPv4/IPv6 textual forms,
/// - `TransportParameterCodecError` (the core's typed error) -> the adapter's
///   `TransportParameterError`, rewrapped at the `Data` boundary.
///
/// The wire format is produced entirely by the core, so it is byte-for-byte
/// identical to the prior implementation; the IPv6 textual form is the RFC 5952
/// canonical produced by ``IPAddressCodec/formatIPv6(_:)`` (matching `inet_ntop`).

import Foundation
import QUICCore
import QUICConnectionCore

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
    public static let minMaxUDPPayloadSize: UInt64 = TransportParameterCodecCore.minMaxUDPPayloadSize

    /// Maximum value for ack_delay_exponent
    public static let maxAckDelayExponent: UInt64 = TransportParameterCodecCore.maxAckDelayExponent

    /// Maximum value for max_ack_delay (2^14 - 1)
    public static let maxMaxAckDelay: UInt64 = TransportParameterCodecCore.maxMaxAckDelay

    /// Minimum value for active_connection_id_limit
    public static let minActiveConnectionIDLimit: UInt64 = TransportParameterCodecCore.minActiveConnectionIDLimit

    /// Maximum value we will honor for active_connection_id_limit.
    ///
    /// RFC 9000 §18.2 does not bound this parameter, but it directly sizes the number of
    /// peer connection IDs we are willing to store. An unbounded value would let a peer flood
    /// us with NEW_CONNECTION_ID frames and exhaust memory. We therefore cap the effective
    /// limit to a small, practical maximum (a single migration rarely needs more than a
    /// handful of CIDs). This is a local resource bound on a control parameter, not an error:
    /// a peer advertising a larger willingness is simply honored up to this ceiling.
    public static let maxActiveConnectionIDLimit: UInt64 = TransportParameterCodecCore.maxActiveConnectionIDLimit

    // MARK: - Encoding

    /// Encode transport parameters for TLS extension
    /// - Parameter params: Transport parameters to encode
    /// - Returns: Encoded bytes (without TLS extension header)
    public static func encode(_ params: TransportParameters) -> Data {
        Data(TransportParameterCodecCore.encode(toCore(params)))
    }

    // MARK: - Decoding

    /// Decode transport parameters from TLS extension data
    /// - Parameter data: Encoded transport parameters
    /// - Returns: Decoded TransportParameters
    /// - Throws: `TransportParameterError` on decode failure
    public static func decode(_ data: Data) throws -> TransportParameters {
        let core: TransportParametersCore
        do {
            core = try TransportParameterCodecCore.decode([UInt8](data))
        } catch {
            // Map the core's typed error onto the adapter's public error type.
            switch error {
            case .duplicateParameter(let id):
                throw TransportParameterError.duplicateParameter(id)
            case .invalidValue(let parameter, let reason):
                throw TransportParameterError.invalidValue(parameter: parameter, reason: reason)
            case .insufficientData:
                throw TransportParameterError.insufficientData
            case .decodeError(let message):
                throw TransportParameterError.decodeError(message)
            }
        }
        return try fromCore(core)
    }

    // MARK: - IPv6 Address Helpers (kept for direct test/call-site use)

    /// Parses an IPv6 textual address into its 16-byte network representation.
    /// - Returns: 16 bytes, or `nil` if the string is not a valid IPv6 literal.
    static func parseIPv6(_ string: String) -> [UInt8]? {
        IPAddressCodec.parseIPv6(string)
    }

    /// Formats a 16-byte IPv6 network representation into its canonical textual form.
    /// - Returns: The textual address, or `nil` if the byte count is wrong or formatting fails.
    static func formatIPv6(_ bytes: [UInt8]) -> String? {
        IPAddressCodec.formatIPv6(bytes)
    }

    // MARK: - Core <-> adapter bridging

    /// Converts the adapter's `TransportParameters` (String IP fields, `Data`
    /// tokens) into the core's wire-byte form.
    private static func toCore(_ params: TransportParameters) -> TransportParametersCore {
        var core = TransportParametersCore()
        core.originalDestinationConnectionID = params.originalDestinationConnectionID
        core.maxIdleTimeout = params.maxIdleTimeout
        core.statelessResetToken = params.statelessResetToken.map { [UInt8]($0) }
        core.maxUDPPayloadSize = params.maxUDPPayloadSize
        core.initialMaxData = params.initialMaxData
        core.initialMaxStreamDataBidiLocal = params.initialMaxStreamDataBidiLocal
        core.initialMaxStreamDataBidiRemote = params.initialMaxStreamDataBidiRemote
        core.initialMaxStreamDataUni = params.initialMaxStreamDataUni
        core.initialMaxStreamsBidi = params.initialMaxStreamsBidi
        core.initialMaxStreamsUni = params.initialMaxStreamsUni
        core.ackDelayExponent = params.ackDelayExponent
        core.maxAckDelay = params.maxAckDelay
        core.disableActiveMigration = params.disableActiveMigration
        core.preferredAddress = params.preferredAddress.map(toCorePreferred)
        core.activeConnectionIDLimit = params.activeConnectionIDLimit
        core.initialSourceConnectionID = params.initialSourceConnectionID
        core.retrySourceConnectionID = params.retrySourceConnectionID
        core.maxDatagramFrameSize = params.maxDatagramFrameSize
        return core
    }

    /// Converts a core `PreferredAddressCore` into the adapter `PreferredAddress`,
    /// formatting the IP byte fields back to their textual forms.
    private static func fromCorePreferred(_ core: PreferredAddressCore) throws -> PreferredAddress {
        let ipv4: String?
        if let bytes = core.ipv4Address {
            // 4 raw bytes always format; a wrong count is a programming error in the core.
            guard let formatted = IPAddressCodec.formatIPv4(bytes) else {
                throw TransportParameterError.decodeError("Invalid preferred address IPv4 bytes")
            }
            ipv4 = formatted
        } else {
            ipv4 = nil
        }

        let ipv6: String?
        if let bytes = core.ipv6Address {
            guard let formatted = IPAddressCodec.formatIPv6(bytes) else {
                throw TransportParameterError.decodeError("Invalid preferred address IPv6 bytes")
            }
            ipv6 = formatted
        } else {
            ipv6 = nil
        }

        return PreferredAddress(
            ipv4Address: ipv4,
            ipv4Port: core.ipv4Port,
            ipv6Address: ipv6,
            ipv6Port: core.ipv6Port,
            connectionID: core.connectionID,
            statelessResetToken: Data(core.statelessResetToken)
        )
    }

    /// Converts the adapter `PreferredAddress` (String IP fields) into the core's
    /// wire-byte form. A non-parseable textual address is a caller error
    /// (`PreferredAddress` should hold a valid literal); we flag it in debug and
    /// encode the family as absent (all-zero) rather than emitting garbage — the
    /// same fail-safe the prior implementation used.
    private static func toCorePreferred(_ addr: PreferredAddress) -> PreferredAddressCore {
        let ipv4Bytes: [UInt8]?
        let ipv4Port: UInt16?
        if let ipv4 = addr.ipv4Address, let port = addr.ipv4Port,
           let bytes = IPAddressCodec.parseIPv4(ipv4) {
            ipv4Bytes = bytes
            ipv4Port = port
        } else {
            assert(addr.ipv4Address == nil, "PreferredAddress.ipv4Address must be a valid IPv4 literal")
            ipv4Bytes = nil
            ipv4Port = nil
        }

        let ipv6Bytes: [UInt8]?
        let ipv6Port: UInt16?
        if let ipv6 = addr.ipv6Address, let port = addr.ipv6Port,
           let bytes = IPAddressCodec.parseIPv6(ipv6) {
            ipv6Bytes = bytes
            ipv6Port = port
        } else {
            assert(addr.ipv6Address == nil, "PreferredAddress.ipv6Address must be a valid IPv6 literal")
            ipv6Bytes = nil
            ipv6Port = nil
        }

        return PreferredAddressCore(
            ipv4Address: ipv4Bytes,
            ipv4Port: ipv4Port,
            ipv6Address: ipv6Bytes,
            ipv6Port: ipv6Port,
            connectionID: addr.connectionID,
            statelessResetToken: [UInt8](addr.statelessResetToken)
        )
    }

    /// Converts the core's wire-byte parameters back into the adapter form.
    private static func fromCore(_ core: TransportParametersCore) throws -> TransportParameters {
        var params = TransportParameters()
        params.originalDestinationConnectionID = core.originalDestinationConnectionID
        params.maxIdleTimeout = core.maxIdleTimeout
        params.statelessResetToken = core.statelessResetToken.map(Data.init)
        params.maxUDPPayloadSize = core.maxUDPPayloadSize
        params.initialMaxData = core.initialMaxData
        params.initialMaxStreamDataBidiLocal = core.initialMaxStreamDataBidiLocal
        params.initialMaxStreamDataBidiRemote = core.initialMaxStreamDataBidiRemote
        params.initialMaxStreamDataUni = core.initialMaxStreamDataUni
        params.initialMaxStreamsBidi = core.initialMaxStreamsBidi
        params.initialMaxStreamsUni = core.initialMaxStreamsUni
        params.ackDelayExponent = core.ackDelayExponent
        params.maxAckDelay = core.maxAckDelay
        params.disableActiveMigration = core.disableActiveMigration
        params.preferredAddress = try core.preferredAddress.map(fromCorePreferred)
        params.activeConnectionIDLimit = core.activeConnectionIDLimit
        params.initialSourceConnectionID = core.initialSourceConnectionID
        params.retrySourceConnectionID = core.retrySourceConnectionID
        params.maxDatagramFrameSize = core.maxDatagramFrameSize
        return params
    }
}
