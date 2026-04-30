import Foundation
import Crypto

enum SecureRandom {
    static func bytes(count: Int) -> Data {
        precondition(count >= 0, "Random byte count must be non-negative")
        guard count > 0 else {
            return Data()
        }
        var output = Data(capacity: count)
        while output.count < count {
            let key = SymmetricKey(size: .bits256)
            let chunk = key.withUnsafeBytes { Data(Array($0)) }
            output.append(chunk.prefix(count - output.count))
        }
        return output
    }

    static func uint32() -> UInt32 {
        let bytes = [UInt8](bytes(count: 4))
        return UInt32(bytes[0])
            | UInt32(bytes[1]) << 8
            | UInt32(bytes[2]) << 16
            | UInt32(bytes[3]) << 24
    }
}
