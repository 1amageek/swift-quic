/// `[UInt8]` ⇄ `Data` equality bridges.
///
/// The moved core types expose byte payloads as `[UInt8]` (e.g.
/// `ConnectionID.bytes`, `LongHeader.token`, `ProtectedLongHeader.retryIntegrityTag`).
/// Existing call sites and tests compare those against `Data` literals
/// (`cid.bytes == Data([...])`, `header.token == Data([...])`). These overloads
/// make `[UInt8] == Data` (and the optional forms) compile with the historical
/// semantics — an element-wise comparison, never a silent type coercion.

import Foundation

@inlinable
public func == (lhs: [UInt8], rhs: Data) -> Bool {
    lhs.count == rhs.count && rhs.elementsEqual(lhs)
}

@inlinable
public func == (lhs: Data, rhs: [UInt8]) -> Bool {
    lhs.count == rhs.count && lhs.elementsEqual(rhs)
}

@inlinable
public func != (lhs: [UInt8], rhs: Data) -> Bool {
    !(lhs == rhs)
}

@inlinable
public func != (lhs: Data, rhs: [UInt8]) -> Bool {
    !(lhs == rhs)
}

@inlinable
public func == (lhs: [UInt8]?, rhs: Data?) -> Bool {
    switch (lhs, rhs) {
    case (nil, nil): return true
    case let (l?, r?): return l == r
    default: return false
    }
}

@inlinable
public func == (lhs: Data?, rhs: [UInt8]?) -> Bool {
    rhs == lhs
}

@inlinable
public func != (lhs: [UInt8]?, rhs: Data?) -> Bool {
    !(lhs == rhs)
}

@inlinable
public func != (lhs: Data?, rhs: [UInt8]?) -> Bool {
    !(lhs == rhs)
}
