import Foundation
import Testing
@testable import QUICCore
@testable import QUICCrypto

@Suite("QUIC CRYPTO TLS message boundary")
struct CryptoStreamMessageTests {
    @Test("Retains a partial header until a complete message arrives")
    func partialHeader() throws {
        var stream = CryptoStream()
        try stream.receive(
            CryptoFrame(offset: 0, data: [0x01, 0x00])
        )
        #expect(try stream.read() == nil)

        try stream.receive(
            CryptoFrame(offset: 2, data: [0x00, 0x02, 0xaa, 0xbb])
        )
        #expect(
            try stream.read() == Data([0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb])
        )
        #expect(try stream.read() == nil)
    }

    @Test("Emits one complete message and retains following messages")
    func multipleMessages() throws {
        var stream = CryptoStream()
        let first = Data([0x01, 0x00, 0x00, 0x01, 0x10])
        let second = Data([0x02, 0x00, 0x00, 0x02, 0x20, 0x21])
        try stream.receive(
            CryptoFrame(offset: 0, data: [UInt8](first + second))
        )

        #expect(try stream.read() == first)
        #expect(try stream.read() == second)
        #expect(try stream.read() == nil)
    }

    @Test("Rejects a message larger than the configured CRYPTO policy")
    func messageSizeLimit() throws {
        var stream = CryptoStream(maxBufferSize: 8)
        try stream.receive(
            CryptoFrame(
                offset: 0,
                data: [0x01, 0x00, 0x00, 0x09]
            )
        )

        do {
            _ = try stream.read()
            Issue.record("an oversized TLS handshake message was accepted")
        } catch let error as CryptoStreamError {
            guard case .messageTooLarge(actual: 13, maximum: 8) = error else {
                Issue.record("unexpected error: \(error)")
                return
            }
        }
    }

    @Test("Rejects conflicting CRYPTO overlap without mutating state")
    func conflictingOverlap() throws {
        var stream = CryptoStream()
        try stream.receive(CryptoFrame(offset: 0, data: [0x01, 0x02, 0x03]))

        do {
            try stream.receive(CryptoFrame(offset: 1, data: [0x09, 0x03]))
            Issue.record("conflicting overlap was accepted")
        } catch let error as CryptoStreamError {
            guard case .conflictingOverlap(offset: 1) = error else {
                Issue.record("unexpected error: \(error)")
                return
            }
        }

        #expect(stream.bufferedBytes == 3)
        #expect(stream.peek() == Data([0x01, 0x02, 0x03]))
    }
}
