/// TLS 1.3 Early Data — adapter-side connection state.
///
/// The wire types (`EarlyDataExtension`, `EndOfEarlyData`) now live in the
/// Embedded-clean `QUICTLSCore` and are re-exported via `HandshakeMessage.swift`.
/// This file keeps only `EarlyDataState`, which holds the client early traffic
/// secret (`Data`) and therefore stays in the Foundation-bearing adapter.

import Foundation
import QUICTLSCore

// MARK: - Early Data State

/// State tracking for 0-RTT early data
public struct EarlyDataState: Sendable {
    /// Whether early data is being attempted
    public var attemptingEarlyData: Bool = false

    /// Whether server accepted early data
    public var earlyDataAccepted: Bool = false

    /// Maximum early data size from ticket
    public var maxEarlyDataSize: UInt32 = 0

    /// Amount of early data sent
    public var earlyDataSent: UInt32 = 0

    /// Client early traffic secret (for 0-RTT encryption)
    public var clientEarlyTrafficSecret: Data?

    public init() {}

    /// Check if more early data can be sent
    public var canSendMoreEarlyData: Bool {
        guard attemptingEarlyData else { return false }
        guard maxEarlyDataSize > 0 else { return false }
        return earlyDataSent < maxEarlyDataSize
    }

    /// Record early data being sent
    public mutating func recordEarlyData(size: UInt32) {
        earlyDataSent = earlyDataSent.addingReportingOverflow(size).partialValue
    }
}
