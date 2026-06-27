/// QUICCrypto-internal `Span<UInt8>` → `[UInt8]` bulk copy.
///
/// The DER ECDSA signature schemes (``QUICDERSignatureP256`` /
/// ``QUICDERSignatureP384``) bridge the protocol's borrowed `Span<UInt8>` surface
/// into swift-crypto's `Data` / `[UInt8]` APIs. swift-p2p-crypto keeps its own
/// equivalent extension *internal* to `P2PCryptoFoundationEssentials`, so QUICCrypto defines
/// its own here to avoid depending on another module's internal symbol.
///
/// The copy is a single bulk `update(from:)` (one `memcpy`-class operation), never
/// the element-wise `for`-append loop that regresses throughput.
import P2PCoreBytes

extension Span where Element == UInt8 {
    /// Copies the borrowed span into an owned array in one bulk copy.
    @inline(__always)
    func quicDERArray() -> [UInt8] {
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
