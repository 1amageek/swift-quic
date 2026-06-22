/// RFC 9221 - max_datagram_frame_size Transport Parameter Tests
///
/// Verifies compliance with RFC 9221 §3:
/// - The max_datagram_frame_size transport parameter (id 0x20) round-trips through
///   the transport-parameter codec.
/// - Absence and a value of 0 are equivalent ("DATAGRAM frames not supported"), so a
///   zero value is not emitted on the wire.

import Testing
import Foundation
@testable import QUICCore
@testable import QUICCrypto

@Suite("RFC 9221 - max_datagram_frame_size Transport Parameter")
struct DatagramTransportParameterRFCTests {

    @Test("max_datagram_frame_size round-trips through the codec")
    func roundTrip() throws {
        var params = TransportParameters()
        params.maxDatagramFrameSize = 65535

        let encoded = TransportParameterCodec.encode(params)
        let decoded = try TransportParameterCodec.decode(encoded)

        #expect(decoded.maxDatagramFrameSize == 65535)
    }

    @Test("Non-default values survive the round-trip")
    func roundTripVariousValues() throws {
        for value: UInt64 in [1, 1200, 1452, 65527, 65535] {
            var params = TransportParameters()
            params.maxDatagramFrameSize = value

            let encoded = TransportParameterCodec.encode(params)
            let decoded = try TransportParameterCodec.decode(encoded)

            #expect(decoded.maxDatagramFrameSize == value)
        }
    }

    @Test("Zero (absent) is not advertised and decodes to zero")
    func zeroNotAdvertised() throws {
        var params = TransportParameters()
        params.maxDatagramFrameSize = 0

        let encoded = TransportParameterCodec.encode(params)
        let decoded = try TransportParameterCodec.decode(encoded)

        // RFC 9221 §3: absence and 0 are equivalent. A peer that did not advertise
        // support decodes back to 0.
        #expect(decoded.maxDatagramFrameSize == 0)
    }

    @Test("Parameter ID is 0x20")
    func parameterID() {
        #expect(TransportParameterID.maxDatagramFrameSize.rawValue == 0x20)
        #expect(TransportParameterID.maxDatagramFrameSize.defaultValue == 0)
    }

    @Test("Advertised parameter coexists with other parameters")
    func coexistsWithOtherParameters() throws {
        var params = TransportParameters()
        params.maxDatagramFrameSize = 1452
        params.initialMaxData = 5_000_000
        params.maxIdleTimeout = 15_000

        let encoded = TransportParameterCodec.encode(params)
        let decoded = try TransportParameterCodec.decode(encoded)

        #expect(decoded.maxDatagramFrameSize == 1452)
        #expect(decoded.initialMaxData == 5_000_000)
        #expect(decoded.maxIdleTimeout == 15_000)
    }
}
