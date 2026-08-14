import SSLCrypto

/// Errors raised by QUIC packet protection and its key schedule.
public enum PacketProtectionError: Error, Equatable, Sendable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidIVLength(expected: Int, actual: Int)
    case invalidHeaderProtectionKeyLength(expected: Int, actual: Int)
    case invalidDerivationOutputLength(actual: Int)
    case labelTooLong(limit: Int, actual: Int)
    case contextTooLong(limit: Int, actual: Int)
    case insufficientSample(expected: Int, actual: Int)
    case ciphertextTooShort(minimum: Int, actual: Int)
    case unsupportedRetryVersion(UInt32)
    case invalidRetryConnectionIDLength(actual: Int)
    case invalidRetryIntegrityTagLength(expected: Int, actual: Int)
    case aead(AEADError)
    case headerProtection(AEADError)
    case keyDerivation(HKDFError)
}
