/// Anti-Amplification Limit (RFC 9000 Section 8.1)
///
/// Before address validation is complete, an endpoint MUST NOT send
/// more than three times the number of bytes received, to prevent
/// amplification attacks.
///
/// This limit applies only to servers during the handshake:
/// - Servers must limit response size until client address is validated
/// - Clients are not subject to this limit (they initiate the connection)
/// - The limit is lifted once the handshake is confirmed
///
/// ## Usage
///
/// ```swift
/// let limiter = AntiAmplificationLimiter(isServer: true)
///
/// // When receiving data
/// limiter.recordBytesReceived(1200)
///
/// // Before sending, check if allowed
/// if limiter.canSend(bytes: 1200) {
///     // Send the packet
///     limiter.recordBytesSent(1200)
/// }
///
/// // After handshake completion
/// limiter.confirmHandshake()
/// ```

import Foundation
import Synchronization
import QUICRecoveryCore

/// Manages the anti-amplification limit for QUIC connections
///
/// RFC 9000 Section 8.1: Address Validation during Connection Establishment
///
/// ## Caller-locked core
///
/// The RFC 9000 §8.1 byte accounting lives in the Embedded-clean value type
/// `QUICRecoveryCore.AntiAmplificationCore`. This class is the host adapter: it keeps
/// the `Mutex` and delegates every query/mutation to the core under the lock. Public
/// API and observable behavior (including overflow saturation) are unchanged.
public final class AntiAmplificationLimiter: Sendable {

    private let core: Mutex<AntiAmplificationCore>

    // MARK: - Initialization

    /// Creates an anti-amplification limiter
    ///
    /// - Parameter isServer: Whether this endpoint is a server.
    ///   Only servers are subject to the amplification limit.
    public init(isServer: Bool) {
        self.core = Mutex(AntiAmplificationCore(isServer: isServer))
    }

    // MARK: - Byte Tracking

    /// Records bytes received from the peer
    ///
    /// This increases the allowance for sending data back.
    ///
    /// - Parameter bytes: Number of bytes received
    public func recordBytesReceived(_ bytes: UInt64) {
        core.withLock { $0.recordBytesReceived(bytes) }
    }

    /// Records bytes sent to the peer
    ///
    /// - Parameter bytes: Number of bytes sent
    public func recordBytesSent(_ bytes: UInt64) {
        core.withLock { $0.recordBytesSent(bytes) }
    }

    // MARK: - Limit Checking

    /// Checks if sending the specified number of bytes is allowed
    ///
    /// - Parameter bytes: Number of bytes to send
    /// - Returns: `true` if sending is allowed
    public func canSend(bytes: UInt64) -> Bool {
        core.withLock { $0.canSend(bytes: bytes) }
    }

    /// Gets the maximum bytes that can be sent right now
    ///
    /// - Returns: Maximum bytes allowed, or `UInt64.max` if unlimited
    public func availableSendWindow() -> UInt64 {
        core.withLock { $0.availableSendWindow() }
    }

    /// Whether the endpoint is currently blocked by the amplification limit
    ///
    /// This can happen when:
    /// - Server hasn't received enough data from client
    /// - Server has sent 3x the received amount
    ///
    /// When blocked, the server must wait for more data from the client
    /// to be able to send more.
    public var isBlocked: Bool {
        core.withLock { $0.isBlocked }
    }

    // MARK: - Address Validation

    /// Marks the address as validated, lifting the amplification limit
    ///
    /// This should be called when:
    /// - Server receives Handshake packet (client address validated)
    /// - Or when handshake is confirmed
    public func validateAddress() {
        core.withLock { $0.validateAddress() }
    }

    /// Marks the handshake as confirmed, lifting the amplification limit
    ///
    /// RFC 9001: Once the handshake is confirmed, address validation is complete.
    public func confirmHandshake() {
        validateAddress()
    }

    /// Whether the address has been validated
    public var isAddressValidated: Bool {
        core.withLock { $0.addressValidated }
    }

    // MARK: - Statistics

    /// Total bytes received from peer
    public var bytesReceived: UInt64 {
        core.withLock { $0.bytesReceived }
    }

    /// Total bytes sent to peer
    public var bytesSent: UInt64 {
        core.withLock { $0.bytesSent }
    }

    /// Current send limit (3x received bytes)
    public var sendLimit: UInt64 {
        core.withLock { c in
            c.addressValidated ? UInt64.max : c.sendLimit
        }
    }
}

// MARK: - Debug Support

extension AntiAmplificationLimiter: CustomStringConvertible {
    public var description: String {
        core.withLock { c in
            if !c.isServer {
                return "AntiAmplificationLimiter(client, unlimited)"
            }
            if c.addressValidated {
                return "AntiAmplificationLimiter(server, validated, unlimited)"
            }
            return "AntiAmplificationLimiter(server, received=\(c.bytesReceived), sent=\(c.bytesSent), limit=\(c.sendLimit))"
        }
    }
}
