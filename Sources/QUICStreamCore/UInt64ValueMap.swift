// UInt64ValueMap.swift
// A compact map for QUIC's UInt64 identifiers. Keeping the key concrete avoids
// two-parameter generic metadata in the portable Swift runtime while preserving
// one owned value per key.

/// An insertion-ordered map whose keys are QUIC-style `UInt64` identifiers.
///
/// The implementation deliberately uses contiguous storage. QUIC stream and
/// in-flight packet counts are bounded by transport parameters and congestion
/// control, so the small linear lookup avoids hashing allocations and remains
/// available to Native, WASM, and Embedded builds through one implementation.
public struct UInt64ValueMap<Value: Sendable>: Sendable {
    private struct Entry: Sendable {
        var key: UInt64
        var value: Value
    }

    private var entries: [Entry]

    public init() {
        self.entries = []
    }

    public var isEmpty: Bool { entries.isEmpty }
    public var count: Int { entries.count }

    public subscript(key: UInt64) -> Value? {
        get {
            for entry in entries where entry.key == key {
                return entry.value
            }
            return nil
        }
        set {
            for index in entries.indices where entries[index].key == key {
                if let newValue {
                    entries[index].value = newValue
                } else {
                    entries.remove(at: index)
                }
                return
            }
            if let newValue {
                entries.append(Entry(key: key, value: newValue))
            }
        }
    }

    @discardableResult
    public mutating func removeValue(forKey key: UInt64) -> Value? {
        for index in entries.indices where entries[index].key == key {
            return entries.remove(at: index).value
        }
        return nil
    }

    public mutating func removeAll(keepingCapacity: Bool = false) {
        entries.removeAll(keepingCapacity: keepingCapacity)
    }

    public var keys: [UInt64] {
        var result: [UInt64] = []
        result.reserveCapacity(entries.count)
        for entry in entries {
            result.append(entry.key)
        }
        return result
    }

    public var values: [Value] {
        var result: [Value] = []
        result.reserveCapacity(entries.count)
        for entry in entries {
            result.append(entry.value)
        }
        return result
    }
}
