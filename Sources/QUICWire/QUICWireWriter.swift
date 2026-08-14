import NetworkingCore

/// An owned append-only builder for QUIC wire values.
///
/// QUIC-specific encoders validate their protocol limits before appending. The
/// writer reserves the caller's computed size so common packet and frame paths
/// use one allocation and materialize no intermediate byte containers.
public struct QUICWireWriter: Sendable {
    private var storage: [UInt8]

    public init(reservingCapacity capacity: Int = 0) {
        storage = []
        if capacity > 0 {
            storage.reserveCapacity(capacity)
        }
    }

    public var count: Int { storage.count }

    public mutating func writeByte(_ value: UInt8) {
        storage.append(value)
    }

    public mutating func writeBytes(_ bytes: some Sequence<UInt8>) {
        storage.append(contentsOf: bytes)
    }

    public mutating func writeSpan(_ bytes: Span<UInt8>) {
        storage.reserveCapacity(storage.count + bytes.count)
        bytes.bytes.withUnsafeBytes { source in
            storage.append(contentsOf: source)
        }
    }

    public mutating func writeUInt8(_ value: UInt8) {
        storage.append(value)
    }

    public mutating func writeUInt16(_ value: UInt16) {
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeUInt32(_ value: UInt32) {
        storage.append(UInt8(truncatingIfNeeded: value >> 24))
        storage.append(UInt8(truncatingIfNeeded: value >> 16))
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeVarint(_ value: UInt64) throws(QUICWireError) {
        guard value <= Varint.maxValue else { throw .invalidVarint }
        appendValidatedVarint(value)
    }

    /// Writes a value whose representable range was established by `Varint`'s
    /// validating initializer. This overload is infallible because invalid raw
    /// integers cannot enter it.
    public mutating func writeVarint(_ value: Varint) {
        appendValidatedVarint(value.value)
    }

    private mutating func appendValidatedVarint(_ value: UInt64) {
        switch value {
        case 0...63:
            storage.append(UInt8(value))
        case 64...16_383:
            storage.append(UInt8(0x40 | ((value >> 8) & 0x3F)))
            storage.append(UInt8(truncatingIfNeeded: value))
        case 16_384...1_073_741_823:
            storage.append(UInt8(0x80 | ((value >> 24) & 0x3F)))
            storage.append(UInt8(truncatingIfNeeded: value >> 16))
            storage.append(UInt8(truncatingIfNeeded: value >> 8))
            storage.append(UInt8(truncatingIfNeeded: value))
        default:
            storage.append(UInt8(0xC0 | ((value >> 56) & 0x3F)))
            for shift in stride(from: 48, through: 0, by: -8) {
                storage.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
            }
        }
    }

    public mutating func writeZeroBytes(_ count: Int) {
        guard count > 0 else { return }
        storage.append(contentsOf: repeatElement(UInt8(0), count: count))
    }

    public consuming func finishArray() -> [UInt8] {
        storage
    }
}
