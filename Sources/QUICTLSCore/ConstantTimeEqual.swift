/// Constant-Time Comparison
///
/// Prevents timing side-channel attacks by ensuring comparison time
/// is proportional to the data length, regardless of where differences occur.
///
/// Used for verify_data (Finished messages) in the wire codec.

/// Compare two byte arrays in constant time.
///
/// Returns `true` if and only if both sequences have equal length and
/// identical byte contents. The comparison always examines every byte,
/// preventing timing side-channel leaks.
///
/// - Parameters:
///   - a: First byte array to compare
///   - b: Second byte array to compare
/// - Returns: `true` if the sequences are identical
public func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var result: UInt8 = 0
    for i in 0..<a.count {
        result |= a[i] ^ b[i]
    }
    return result == 0
}
