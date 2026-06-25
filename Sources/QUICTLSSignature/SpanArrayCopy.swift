// SpanArrayCopy.swift
// `Span<UInt8>` -> `[UInt8]` bulk copy for the DER ECDSA signature schemes.
//
// The `isValid` path receives a borrowed `Span<UInt8>` over the wire signature and
// must hand an owned `[UInt8]` to ``ECDSADERConversion/decode(der:scalarLength:)``.
// The copy is a single bulk `update(from:)` (one `memcpy`-class operation), never
// an element-wise append loop that regresses throughput.

import P2PCoreBytes

extension Span where Element == UInt8 {
    /// A fresh `[UInt8]` copy of the span via one bulk fill.
    @inline(__always)
    func tlsSignatureArray() -> [UInt8] {
        let n = count
        guard n > 0 else { return [] }
        return [UInt8](unsafeUninitializedCapacity: n) { destination, initializedCount in
            withUnsafeBufferPointer { source in
                destination.baseAddress!.update(from: source.baseAddress!, count: n)
            }
            initializedCount = n
        }
    }
}
