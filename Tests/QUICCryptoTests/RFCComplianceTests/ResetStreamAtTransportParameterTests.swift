import Foundation
import Testing
@testable import QUICCore
@testable import QUICCrypto

@Suite("QUIC partial-delivery reset transport parameter")
struct ResetStreamAtTransportParameterTests {
    @Test("reset_stream_at emits canonical and quic-go identifiers")
    func roundTrip() throws {
        var parameters = TransportParameters()
        parameters.enableResetStreamAt = true

        let encoded = TransportParameterCodec.encode(parameters)
        let decoded = try TransportParameterCodec.decode(encoded)
        let identifiers = try transportParameterIdentifiers(in: encoded)

        #expect(decoded.enableResetStreamAt)
        #expect(identifiers.count(where: { $0 == 0x1d }) == 1)
        #expect(identifiers.count(where: { $0 == 0x17f7586d2cb571 }) == 1)
    }

    @Test("draft-07 reset_stream_at identifier is normalized")
    func decodesDraft07Identifier() throws {
        let wire = Data([
            0xc0, 0x17, 0xf7, 0x58, 0x6d, 0x2c, 0xb5, 0x71, 0x00,
        ])

        let decoded = try TransportParameterCodec.decode(wire)

        #expect(decoded.enableResetStreamAt)
    }

    @Test("reset_stream_at rejects a non-empty value")
    func rejectsNonEmptyValue() {
        let wire = Data([0x1d, 0x01, 0x00])

        #expect(throws: TransportParameterError.self) {
            _ = try TransportParameterCodec.decode(wire)
        }
    }

    @Test("draft-07 reset_stream_at rejects a non-empty value")
    func rejectsDraft07NonEmptyValue() {
        let wire = Data([
            0xc0, 0x17, 0xf7, 0x58, 0x6d, 0x2c, 0xb5, 0x71, 0x01, 0x00,
        ])

        #expect(throws: TransportParameterError.self) {
            _ = try TransportParameterCodec.decode(wire)
        }
    }

    private func transportParameterIdentifiers(in data: Data) throws -> [UInt64] {
        let bytes = [UInt8](data)
        var offset = 0
        var identifiers: [UInt64] = []

        while offset < bytes.count {
            let (identifier, identifierLength) = try Varint.decode(
                from: Array(bytes[offset...])
            )
            offset += identifierLength

            let (valueLength, valueLengthLength) = try Varint.decode(
                from: Array(bytes[offset...])
            )
            offset += valueLengthLength

            guard valueLength.value <= UInt64(bytes.count - offset) else {
                throw Varint.DecodeError.insufficientData
            }
            identifiers.append(identifier.value)
            offset += Int(valueLength.value)
        }

        return identifiers
    }
}
