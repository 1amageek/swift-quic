/// Opt-in performance measurements for the current QUIC byte path.
///
/// Enable this executable with `SWIFT_QUIC_ENABLE_BENCHMARKS=1`. It is
/// intentionally absent from the default product graph so correctness tests do
/// not pay benchmark cost on every run.

import Foundation
import NetworkingCore
import QUICConnectionCore
import QUICPacketProtectionCore
import QUICWire

@main
enum QUICBenchmarkRunner {
    static func main() throws {
        try varintRoundTripThroughput()
        try streamFrameRoundTripThroughput()
        try coalescedDatagramSplitThroughput()
        try packetProtectionRoundTripThroughput()
        try connectionIDDictionaryLookupThroughput()
    }

    private static func varintRoundTripThroughput() throws {
        let values: [UInt64] = [0, 63, 64, 16_383, 16_384, 1_073_741_823]
        let iterations = 1_500_000
        var checksum: UInt64 = 0

        let started = Date.timeIntervalSinceReferenceDate
        for _ in 0..<iterations {
            for value in values {
                let encoded = try Varint(value).encodeBytes()
                let decoded = try Varint.decode(from: encoded)
                checksum &+= decoded.0.value
            }
        }
        report(
            name: "varint_round_trip",
            operations: iterations * values.count,
            elapsed: Date.timeIntervalSinceReferenceDate - started
        )
        guard checksum != 0 else {
            throw BenchmarkError.invalidChecksum("varint_round_trip")
        }
    }

    private static func streamFrameRoundTripThroughput() throws {
        let codec = StandardFrameCodec()
        let frame = Frame.stream(
            StreamFrame(
                streamID: 4,
                offset: 1_024,
                data: [UInt8](repeating: 0xA5, count: 1_200),
                fin: false,
                hasLength: true
            )
        )
        let iterations = 2_000_000
        var checksum = 0

        let started = Date.timeIntervalSinceReferenceDate
        for _ in 0..<iterations {
            let encoded = try codec.encodeBytes(frame)
            let decoded = try codec.decodeFrames(from: encoded)
            checksum &+= decoded.count
        }
        report(
            name: "stream_frame_round_trip_1200_bytes",
            operations: iterations,
            elapsed: Date.timeIntervalSinceReferenceDate - started
        )
        guard checksum == iterations else {
            throw BenchmarkError.invalidChecksum("stream_frame_round_trip_1200_bytes")
        }
    }

    private static func coalescedDatagramSplitThroughput() throws {
        let datagram = [UInt8](repeating: 0, count: 1_200)
        let iterations = 8_000_000
        var checksum = 0

        let started = Date.timeIntervalSinceReferenceDate
        for _ in 0..<iterations {
            let ranges = try CoalescedDatagramCore.split(
                datagram: datagram.span,
                dcidLength: 8
            )
            checksum &+= ranges[0].length
        }
        report(
            name: "borrowed_datagram_split_1200_bytes",
            operations: iterations,
            elapsed: Date.timeIntervalSinceReferenceDate - started
        )
        guard checksum == iterations * datagram.count else {
            throw BenchmarkError.invalidChecksum("borrowed_datagram_split_1200_bytes")
        }
    }

    private static func connectionIDDictionaryLookupThroughput() throws {
        let identifiers = try (0..<1_000).map { index in
            try ConnectionID(bytes: [
                UInt8((index >> 8) & 0xFF),
                UInt8(index & 0xFF),
                0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ])
        }
        var table: [ConnectionID: Int] = [:]
        table.reserveCapacity(identifiers.count)
        for (index, identifier) in identifiers.enumerated() {
            table[identifier] = index
        }

        let iterations = 10_000
        var checksum = 0
        let started = Date.timeIntervalSinceReferenceDate
        for _ in 0..<iterations {
            for identifier in identifiers {
                guard let value = table[identifier] else {
                    throw BenchmarkError.missingConnectionID
                }
                checksum &+= value
            }
        }
        report(
            name: "connection_id_dictionary_lookup",
            operations: iterations * identifiers.count,
            elapsed: Date.timeIntervalSinceReferenceDate - started
        )
        guard checksum != 0 else {
            throw BenchmarkError.invalidChecksum("connection_id_dictionary_lookup")
        }
    }

    private static func packetProtectionRoundTripThroughput() throws {
        let protector = try QUICKeyDerivation.protector(
            secret: [UInt8](repeating: 0x42, count: 32),
            suite: .aes128GCM
        )
        let header = [UInt8](repeating: 0xA1, count: 13)
        let plaintext = [UInt8](repeating: 0x5A, count: 1_200)
        let iterations = 400_000
        var checksum = 0

        let started = Date.timeIntervalSinceReferenceDate
        for packetNumber in 0..<iterations {
            let ciphertext = try protector.seal(
                plaintext.span,
                packetNumber: UInt64(packetNumber),
                header: header.span
            )
            let opened = try protector.open(
                ciphertext.span,
                packetNumber: UInt64(packetNumber),
                header: header.span
            )
            checksum &+= opened.count
        }
        report(
            name: "aes128_gcm_round_trip_1200_bytes",
            operations: iterations,
            elapsed: Date.timeIntervalSinceReferenceDate - started
        )
        guard checksum == iterations * plaintext.count else {
            throw BenchmarkError.invalidChecksum("aes128_gcm_round_trip_1200_bytes")
        }
    }

    private static func report(name: String, operations: Int, elapsed: TimeInterval) {
        let operationsPerSecond = Double(operations) / elapsed
        print(
            "BENCHMARK name=\(name) operations=\(operations) "
                + "elapsed_seconds=\(elapsed) ops_per_second=\(operationsPerSecond)"
        )
    }
}

private enum BenchmarkError: Error {
    case invalidChecksum(String)
    case missingConnectionID
}
