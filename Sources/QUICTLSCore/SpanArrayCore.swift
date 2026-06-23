/// Embedded-clean `Span<UInt8>` → `[UInt8]` copy helper for `QUICTLSCore`.
///
/// Several core operations need a contiguous owned `[UInt8]` (e.g. to feed the
/// `[UInt8]`-based CertificateVerify signed-input builder). This copies
/// element-by-element so it works under Embedded Swift with no Foundation,
/// no `any`, no swift-crypto.

import P2PCoreBytes

extension Span where Element == UInt8 {
    /// Copies the span into a fresh `[UInt8]`.
    @inline(__always)
    func providerArrayCore() -> [UInt8] {
        var array = [UInt8]()
        array.reserveCapacity(count)
        for index in 0..<count { array.append(self[index]) }
        return array
    }
}
