import Foundation
import Crypto

enum ConnectionSecureRandom {
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
}
