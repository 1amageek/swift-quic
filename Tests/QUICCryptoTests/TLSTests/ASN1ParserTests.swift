import Testing
import Foundation
@testable import QUICCrypto

/// Regression tests for `ASN1Parser` hardening against malformed/adversarial DER.
///
/// These cover two trap classes that must surface as typed `ASN1Error` throws
/// rather than crashing the process:
/// - Long-form length values large enough to overflow `position + length`.
/// - Constructed-TLV nesting deep enough to exhaust the stack.
@Suite("ASN1Parser Hardening Tests")
struct ASN1ParserHardeningTests {

    // MARK: - Overflow

    @Test("Long-form length near Int.max throws instead of trapping")
    func longFormLengthOverflowThrows() throws {
        // Tag = SEQUENCE (0x30, constructed), then a long-form length declaring
        // 8 length octets all 0x7F. That decodes to a length close to Int.max,
        // far beyond the buffer. The old code computed `position + length`, which
        // overflow-traps before the bounds check; the fix validates against the
        // remaining byte count without adding.
        var bytes: [UInt8] = [0x30, 0x88] // 0x88 => long form, 8 length bytes
        bytes.append(contentsOf: [0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        let data = Data(bytes)

        var parser = ASN1Parser(data: data)
        #expect(throws: ASN1Error.self) {
            _ = try parser.parse()
        }
    }

    @Test("Primitive long-form length overflow throws instead of trapping")
    func primitiveLongFormLengthOverflowThrows() throws {
        // Same overflow surface for a primitive tag (OCTET STRING, 0x04).
        var bytes: [UInt8] = [0x04, 0x88]
        bytes.append(contentsOf: [0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        let data = Data(bytes)

        var parser = ASN1Parser(data: data)
        #expect(throws: ASN1Error.self) {
            _ = try parser.parse()
        }
    }

    @Test("Length exceeding remaining bytes throws unexpectedEndOfData")
    func lengthExceedingRemainingThrows() throws {
        // SEQUENCE claiming 10 content bytes but only 2 are present.
        let data = Data([0x30, 0x0A, 0x01, 0x02])
        var parser = ASN1Parser(data: data)
        do {
            _ = try parser.parse()
            Issue.record("Expected ASN1Error.unexpectedEndOfData")
        } catch let error as ASN1Error {
            switch error {
            case .unexpectedEndOfData:
                break
            default:
                Issue.record("Expected unexpectedEndOfData, got \(error)")
            }
        }
    }

    // MARK: - Recursion depth

    @Test("Deeply nested constructed TLVs throw depthLimitExceeded instead of stack overflow")
    func deeplyNestedConstructedThrows() throws {
        // Build a VALID, definite-length DER structure nested far deeper than the
        // parser's depth cap (64): the innermost value is a small INTEGER, wrapped
        // in 500 SEQUENCE layers (lengths computed bottom-up so every layer is
        // well-formed). Without a depth cap, parsing this recurses 500 deep and can
        // overflow the stack; with the cap it must surface a typed throw before
        // reaching that depth. This is the same trap class as `30 80 30 80 ...`
        // but expressed in DER's definite-length form (indefinite length is
        // rejected by this parser).
        let nesting = 500
        var current = Data([0x02, 0x01, 0x2A]) // INTEGER 42
        for _ in 0..<nesting {
            var wrapped: [UInt8] = [0x30] // SEQUENCE
            wrapped.append(contentsOf: derLength(current.count))
            wrapped.append(contentsOf: current)
            current = Data(wrapped)
        }

        var parser = ASN1Parser(data: current)
        do {
            _ = try parser.parse()
            Issue.record("Expected ASN1Error.depthLimitExceeded")
        } catch let error as ASN1Error {
            switch error {
            case .depthLimitExceeded:
                break
            default:
                Issue.record("Expected depthLimitExceeded, got \(error)")
            }
        }
    }

    // MARK: - Well-formed input still parses

    @Test("Well-formed nested SEQUENCE still parses correctly")
    func wellFormedNestedParses() throws {
        // SEQUENCE { INTEGER 1, OCTET STRING { 0xAA 0xBB } }
        let inner = Data([
            0x02, 0x01, 0x01,        // INTEGER 1
            0x04, 0x02, 0xAA, 0xBB   // OCTET STRING AA BB
        ])
        var seq: [UInt8] = [0x30, UInt8(inner.count)]
        seq.append(contentsOf: inner)
        let data = Data(seq)

        let value = try ASN1Parser.parseOne(from: data)
        #expect(value.tag.isConstructed)
        #expect(value.children.count == 2)
    }

    @Test("Moderately nested constructed TLVs within the cap parse")
    func moderateNestingParses() throws {
        // Build N nested SEQUENCEs, each wrapping the previous, ending in an
        // INTEGER. N is comfortably under the depth cap so this must succeed.
        let depth = 32
        var current = Data([0x02, 0x01, 0x2A]) // INTEGER 42
        for _ in 0..<depth {
            var wrapped: [UInt8] = [0x30, UInt8(current.count)]
            wrapped.append(contentsOf: current)
            current = Data(wrapped)
        }

        let value = try ASN1Parser.parseOne(from: current)
        #expect(value.tag.isConstructed)
    }

    // MARK: - Helpers

    /// Encodes a DER definite length (short form < 128, otherwise long form).
    private func derLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        }
        var bytes: [UInt8] = []
        var remaining = length
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }
}
