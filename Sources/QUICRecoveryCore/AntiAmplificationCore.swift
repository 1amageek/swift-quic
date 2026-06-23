/// Embedded-clean anti-amplification limiter (RFC 9000 §8.1) as a value type.
///
/// Before address validation completes, a server MUST NOT send more than three times
/// the number of bytes received, preventing amplification attacks. This is the
/// byte-identical accounting of the host `AntiAmplificationLimiter`, expressed as a
/// `struct` with saturating arithmetic. The host adapter wraps it in a `Mutex` and
/// exposes the same public API; observable behavior (including overflow saturation) is
/// unchanged.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`.
public struct AntiAmplificationCore: Sendable, Equatable {

    /// Amplification factor (RFC 9000 §8.1 specifies 3).
    public static let amplificationFactor: UInt64 = 3

    /// Total bytes received from the peer (saturating).
    public private(set) var bytesReceived: UInt64

    /// Total bytes sent to the peer (saturating).
    public private(set) var bytesSent: UInt64

    /// Whether address validation has completed (lifts the limit).
    public private(set) var addressValidated: Bool

    /// Whether this endpoint is a server (only servers are limited).
    public let isServer: Bool

    /// Creates an anti-amplification core.
    ///
    /// - Parameter isServer: Whether this endpoint is a server.
    public init(isServer: Bool) {
        self.bytesReceived = 0
        self.bytesSent = 0
        self.addressValidated = false
        self.isServer = isServer
    }

    /// The maximum number of bytes the server may send (saturating at `UInt64.max`).
    public var sendLimit: UInt64 {
        let (result, overflow) = bytesReceived.multipliedReportingOverflow(by: Self.amplificationFactor)
        return overflow ? UInt64.max : result
    }

    /// Remaining bytes that can be sent under the current limit.
    public var remainingAllowance: UInt64 {
        guard sendLimit > bytesSent else { return 0 }
        return sendLimit - bytesSent
    }

    /// Records bytes received from the peer (saturating addition).
    public mutating func recordBytesReceived(_ bytes: UInt64) {
        let (result, overflow) = bytesReceived.addingReportingOverflow(bytes)
        bytesReceived = overflow ? UInt64.max : result
    }

    /// Records bytes sent to the peer (saturating addition).
    public mutating func recordBytesSent(_ bytes: UInt64) {
        let (result, overflow) = bytesSent.addingReportingOverflow(bytes)
        bytesSent = overflow ? UInt64.max : result
    }

    /// Whether sending `bytes` is currently allowed.
    public func canSend(bytes: UInt64) -> Bool {
        // Clients are never limited; once validated, the limit is lifted.
        guard isServer else { return true }
        guard !addressValidated else { return true }

        let (total, overflow) = bytesSent.addingReportingOverflow(bytes)
        if overflow { return false }
        return total <= sendLimit
    }

    /// Maximum bytes sendable right now (`UInt64.max` when unlimited).
    public func availableSendWindow() -> UInt64 {
        guard isServer else { return UInt64.max }
        guard !addressValidated else { return UInt64.max }
        return remainingAllowance
    }

    /// Whether the endpoint is currently blocked by the amplification limit.
    public var isBlocked: Bool {
        guard isServer && !addressValidated else { return false }
        return remainingAllowance == 0
    }

    /// Marks the address as validated, lifting the limit.
    public mutating func validateAddress() {
        addressValidated = true
    }
}
