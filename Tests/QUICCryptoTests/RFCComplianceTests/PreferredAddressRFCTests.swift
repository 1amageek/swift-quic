/// RFC 9000 Section 18.2 - Preferred Address Transport Parameter Tests
///
/// These tests verify compliance with RFC 9000 Section 18.2:
/// - preferred_address transport parameter encoding/decoding
/// - IPv4 and IPv6 address handling
/// - Connection ID and stateless reset token in preferred address

import Testing
import Foundation
@testable import QUICCore
@testable import QUICCrypto

@Suite("RFC 9000 §18.2 - Preferred Address Compliance")
struct PreferredAddressRFCTests {

    // MARK: - RFC 9000 §18.2: Parameter Format

    @Test("Preferred address contains all required fields")
    func preferredAddressRequiredFields() throws {
        // RFC 9000 §18.2: The preferred_address transport parameter contains
        // an IPv4 address, an IPv6 address, and associated port numbers,
        // a connection ID, and a stateless reset token.

        let cid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
        let resetToken = Data(repeating: 0xAA, count: 16)

        let preferred = PreferredAddress(
            ipv4Address: "192.168.1.1",
            ipv4Port: 443,
            ipv6Address: "2001:db8::1",
            ipv6Port: 443,
            connectionID: cid,
            statelessResetToken: resetToken
        )

        #expect(preferred.ipv4Address != nil, "IPv4 address MUST be present")
        #expect(preferred.ipv4Port != nil, "IPv4 port MUST be present")
        #expect(preferred.connectionID.length > 0, "Connection ID MUST be present")
        #expect(preferred.statelessResetToken.count == 16, "Stateless reset token MUST be 16 bytes")
    }

    // MARK: - Transport Parameter Encoding/Decoding

    @Test("Preferred address encodes and decodes correctly")
    func preferredAddressRoundtrip() throws {
        // Create transport parameters with preferred address

        var params = TransportParameters()
        params.maxIdleTimeout = 30000
        params.initialMaxData = 1_000_000

        // Set preferred address with IPv4
        params.preferredAddress = PreferredAddress(
            ipv4Address: "203.0.113.1",  // TEST-NET-3
            ipv4Port: 443,
            ipv6Address: nil,  // No IPv6
            ipv6Port: nil,
            connectionID: try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04])),
            statelessResetToken: Data(repeating: 0xBB, count: 16)
        )

        // Encode
        let encoded = TransportParameterCodec.encode(params)
        #expect(!encoded.isEmpty)

        // Decode
        let decoded = try TransportParameterCodec.decode(encoded)

        // Verify preferred address was preserved
        #expect(decoded.preferredAddress != nil, "Preferred address should be decoded")
        #expect(decoded.preferredAddress?.ipv4Address == "203.0.113.1")
        #expect(decoded.preferredAddress?.ipv4Port == 443)
        #expect(decoded.preferredAddress?.connectionID.bytes == Data([0x01, 0x02, 0x03, 0x04]))
    }

    @Test("Preferred address with IPv6 encodes correctly")
    func preferredAddressWithIPv6() throws {
        // RFC 9000: The server's preferred address includes BOTH IPv4 and IPv6

        var params = TransportParameters()

        params.preferredAddress = PreferredAddress(
            ipv4Address: "192.0.2.1",  // TEST-NET-1
            ipv4Port: 443,
            ipv6Address: "2001:db8::1",
            ipv6Port: 8443,
            connectionID: try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])),
            statelessResetToken: Data(repeating: 0xCC, count: 16)
        )

        // Encode and decode
        let encoded = TransportParameterCodec.encode(params)
        let decoded = try TransportParameterCodec.decode(encoded)

        // IPv6 is now fully implemented: the address MUST round-trip, not be silently zeroed.
        #expect(decoded.preferredAddress != nil)
        #expect(decoded.preferredAddress?.ipv4Address != nil)
        #expect(decoded.preferredAddress?.ipv6Address != nil, "IPv6 address MUST be preserved")
        // Canonical form of "2001:db8::1" is "2001:db8::1".
        #expect(decoded.preferredAddress?.ipv6Address == "2001:db8::1")
        #expect(decoded.preferredAddress?.ipv6Port == 8443)
    }

    // MARK: - IPv6 Full Round-Trip (RFC 9000 §18.2)

    @Test("IPv6 preferred address round-trips through encode/decode")
    func ipv6PreferredAddressRoundTrip() throws {
        var params = TransportParameters()
        let token = Data(repeating: 0x5A, count: 16)
        params.preferredAddress = PreferredAddress(
            ipv4Address: nil,
            ipv4Port: nil,
            ipv6Address: "2001:db8:85a3::8a2e:370:7334",
            ipv6Port: 8443,
            connectionID: try ConnectionID(bytes: Data([0xAA, 0xBB, 0xCC, 0xDD])),
            statelessResetToken: token
        )

        let encoded = TransportParameterCodec.encode(params)
        let decoded = try TransportParameterCodec.decode(encoded)

        let addr = try #require(decoded.preferredAddress)
        // IPv4 family was absent -> decodes back to nil (not "0.0.0.0").
        #expect(addr.ipv4Address == nil)
        #expect(addr.ipv4Port == nil)
        // IPv6 is preserved in canonical form and is usable.
        #expect(addr.ipv6Address == "2001:db8:85a3::8a2e:370:7334")
        #expect(addr.ipv6Port == 8443)
        #expect(addr.connectionID.bytes == Data([0xAA, 0xBB, 0xCC, 0xDD]))
        #expect(addr.statelessResetToken == token)
    }

    @Test("Dual-stack preferred address round-trips both families")
    func dualStackPreferredAddressRoundTrip() throws {
        var params = TransportParameters()
        params.preferredAddress = PreferredAddress(
            ipv4Address: "203.0.113.7",
            ipv4Port: 443,
            ipv6Address: "::1",
            ipv6Port: 4433,
            connectionID: try ConnectionID(bytes: Data([0x01, 0x02])),
            statelessResetToken: Data(repeating: 0x00, count: 16)
        )

        let decoded = try TransportParameterCodec.decode(TransportParameterCodec.encode(params))
        let addr = try #require(decoded.preferredAddress)
        #expect(addr.ipv4Address == "203.0.113.7")
        #expect(addr.ipv4Port == 443)
        #expect(addr.ipv6Address == "::1")
        #expect(addr.ipv6Port == 4433)
    }

    @Test("parseIPv6/formatIPv6 are inverse for canonical literals")
    func ipv6ParseFormatRoundTrip() throws {
        let literals = ["::1", "2001:db8::1", "fe80::1", "2001:db8:85a3::8a2e:370:7334"]
        for literal in literals {
            let bytes = try #require(TransportParameterCodec.parseIPv6(literal), "parse \(literal)")
            #expect(bytes.count == 16)
            let formatted = try #require(TransportParameterCodec.formatIPv6(bytes), "format \(literal)")
            // Re-parse to compare in byte space (avoids textual canonicalization differences).
            #expect(TransportParameterCodec.parseIPv6(formatted) == bytes)
        }
    }

    @Test("Invalid IPv6 literal fails to parse")
    func invalidIPv6FailsToParse() {
        #expect(TransportParameterCodec.parseIPv6("not-an-address") == nil)
        #expect(TransportParameterCodec.parseIPv6("12345::xyz") == nil)
    }

    @Test("formatIPv6 renders embedded-IPv4 dotted-quad tail like inet_ntop")
    func ipv6EmbeddedIPv4Formatting() throws {
        // IPv4-mapped: must format as ::ffff:192.168.0.1, NOT ::ffff:c0a8:1.
        let mapped = try #require(TransportParameterCodec.parseIPv6("::ffff:192.168.0.1"))
        #expect(TransportParameterCodec.formatIPv6(mapped) == "::ffff:192.168.0.1")

        // IPv4-compatible: must format as ::1.2.3.4, NOT ::1:203.
        let compatible = try #require(TransportParameterCodec.parseIPv6("::1.2.3.4"))
        #expect(TransportParameterCodec.formatIPv6(compatible) == "::1.2.3.4")

        // Loopback, all-zero, and normal IPv6 are unchanged (plain hextets).
        let loopback = try #require(TransportParameterCodec.parseIPv6("::1"))
        #expect(TransportParameterCodec.formatIPv6(loopback) == "::1")

        let unspecified = try #require(TransportParameterCodec.parseIPv6("::"))
        #expect(TransportParameterCodec.formatIPv6(unspecified) == "::")

        let normal = try #require(TransportParameterCodec.parseIPv6("2001:db8::1"))
        #expect(TransportParameterCodec.formatIPv6(normal) == "2001:db8::1")
    }

    // MARK: - Client-Only Requirement

    @Test("Client MUST NOT send preferred_address")
    func clientMustNotSendPreferredAddress() throws {
        // RFC 9000 §18.2: This transport parameter is only sent by a server.
        // A client MUST treat receipt of a preferred_address transport parameter
        // as a connection error of type TRANSPORT_PARAMETER_ERROR.

        // Server encoding IS allowed:
        var serverParams = TransportParameters()

        serverParams.preferredAddress = PreferredAddress(
            ipv4Address: "10.0.0.1",
            ipv4Port: 443,
            ipv6Address: nil,
            ipv6Port: nil,
            connectionID: try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04])),
            statelessResetToken: Data(repeating: 0xDD, count: 16)
        )

        // Server can encode with preferred_address
        let encoded = TransportParameterCodec.encode(serverParams)
        #expect(!encoded.isEmpty)

        // But a CLIENT decoder receiving this from another client should reject it
        // (The validation depends on knowing the peer role during decoding)
    }

    // MARK: - Connection ID in Preferred Address

    @Test("Preferred address connection ID is valid")
    func preferredAddressConnectionIDValid() throws {
        // RFC 9000 §18.2: The connection ID field is a connection ID that
        // the client can use to reach the server at the preferred address.

        // CID must be 1-20 bytes
        for length in 1...20 {
            let cidBytes = Data(repeating: 0x42, count: length)
            let cid = try ConnectionID(bytes: cidBytes)

            let preferred = PreferredAddress(
                ipv4Address: "127.0.0.1",
                ipv4Port: 443,
                ipv6Address: nil,
                ipv6Port: nil,
                connectionID: cid,
                statelessResetToken: Data(repeating: 0xEE, count: 16)
            )

            #expect(preferred.connectionID.length == length)
        }
    }

    // MARK: - Stateless Reset Token

    @Test("Preferred address stateless reset token is 16 bytes")
    func preferredAddressStatelessResetToken() throws {
        // RFC 9000 §18.2: Stateless Reset Token: A 16-byte stateless reset token.

        let cid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let resetToken = Data(repeating: 0xFF, count: 16)

        let preferred = PreferredAddress(
            ipv4Address: "10.0.0.1",
            ipv4Port: 443,
            ipv6Address: nil,
            ipv6Port: nil,
            connectionID: cid,
            statelessResetToken: resetToken
        )

        #expect(preferred.statelessResetToken.count == 16)
    }

    // MARK: - Migration Behavior

    @Test("Client uses preferred address after handshake")
    func clientUsesPreferredAddressAfterHandshake() throws {
        // RFC 9000 §18.2: A client MAY choose to use the server's preferred
        // address when the handshake is complete. If the client does choose
        // to use the preferred address, the client MUST use the provided
        // connection ID and stateless reset token.

        let cid = try ConnectionID(bytes: Data([0xAA, 0xBB, 0xCC, 0xDD]))

        let preferred = PreferredAddress(
            ipv4Address: "203.0.113.100",
            ipv4Port: 8443,
            ipv6Address: nil,
            ipv6Port: nil,
            connectionID: cid,
            statelessResetToken: Data(repeating: 0x11, count: 16)
        )

        // After migration, packets to preferred address MUST use provided CID
        #expect(preferred.connectionID == cid)
    }

    // MARK: - Zero Address Handling

    @Test("Nil IPv4 indicates not available")
    func nilIPv4AddressNotAvailable() throws {
        // RFC 9000 §18.2: If a server has no IPv4 address, the IPv4 address
        // field can be omitted or set to zeros.

        let preferred = PreferredAddress(
            ipv4Address: nil,
            ipv4Port: nil,
            ipv6Address: "2001:db8::1",
            ipv6Port: 443,
            connectionID: try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04])),
            statelessResetToken: Data(repeating: 0x00, count: 16)
        )

        #expect(preferred.ipv4Address == nil)
        #expect(preferred.ipv6Address != nil)
    }

    @Test("Nil IPv6 indicates not available")
    func nilIPv6AddressNotAvailable() throws {
        // RFC 9000 §18.2: If a server has no IPv6 address, the IPv6 address
        // field can be omitted or set to zeros.

        let preferred = PreferredAddress(
            ipv4Address: "10.0.0.1",
            ipv4Port: 443,
            ipv6Address: nil,
            ipv6Port: nil,
            connectionID: try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04])),
            statelessResetToken: Data(repeating: 0x00, count: 16)
        )

        #expect(preferred.ipv4Address != nil)
        #expect(preferred.ipv6Address == nil)
    }
}

// MARK: - active_connection_id_limit Upper Bound (RFC 9000 §18.2)

@Suite("RFC 9000 §18.2 - active_connection_id_limit bounds")
struct ActiveConnectionIDLimitBoundTests {

    /// Encodes a single active_connection_id_limit transport parameter on the wire.
    private func encodeActiveConnectionIDLimit(_ value: UInt64) -> Data {
        var body = Data()
        // Parameter id 0x0e = active_connection_id_limit
        Varint(0x0e).encode(to: &body)
        var valueBytes = Data()
        Varint(value).encode(to: &valueBytes)
        Varint(UInt64(valueBytes.count)).encode(to: &body)
        body.append(valueBytes)
        return body
    }

    @Test("Huge active_connection_id_limit is clamped to the ceiling")
    func hugeActiveConnectionIDLimitClamped() throws {
        // A peer advertising an absurd active_connection_id_limit must not relax our
        // peer-CID storage cap without bound. The decoded value is clamped to the ceiling.
        let wire = encodeActiveConnectionIDLimit((1 << 62) - 1)
        let decoded = try TransportParameterCodec.decode(wire)
        #expect(decoded.activeConnectionIDLimit == TransportParameterCodec.maxActiveConnectionIDLimit)
    }

    @Test("In-range active_connection_id_limit is preserved")
    func inRangeActiveConnectionIDLimitPreserved() throws {
        let wire = encodeActiveConnectionIDLimit(4)
        let decoded = try TransportParameterCodec.decode(wire)
        #expect(decoded.activeConnectionIDLimit == 4)
    }

    @Test("active_connection_id_limit below the minimum is rejected")
    func belowMinimumRejected() throws {
        let wire = encodeActiveConnectionIDLimit(1)
        #expect(throws: TransportParameterError.self) {
            _ = try TransportParameterCodec.decode(wire)
        }
    }
}
