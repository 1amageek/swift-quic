import Testing
@testable import QUICConnectionEngineCore

@Suite("QUIC CRYPTO message framing")
struct QUICCryptoMessageFramerTests {
    @Test("Buffers a partial header and emits a complete message")
    func partialMessage() throws {
        var framer = QUICCryptoMessageFramer()
        #expect(try framer.append([0x01, 0x00, 0x00]) == [])
        #expect(
            try framer.append([0x01, 0xaa]) ==
                [[0x01, 0x00, 0x00, 0x01, 0xaa]]
        )
    }

    @Test("Emits multiple messages from one ordered CRYPTO delivery")
    func multipleMessages() throws {
        var framer = QUICCryptoMessageFramer()
        #expect(
            try framer.append([
                0x01, 0x00, 0x00, 0x01, 0xaa,
                0x02, 0x00, 0x00, 0x00,
            ]) == [
                [0x01, 0x00, 0x00, 0x01, 0xaa],
                [0x02, 0x00, 0x00, 0x00],
            ]
        )
    }
}
