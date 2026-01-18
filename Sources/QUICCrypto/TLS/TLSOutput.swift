/// TLS Output Types (RFC 9001)
///
/// Output events from TLS processing during QUIC handshake.

import Foundation
import Crypto
import QUICCore

// MARK: - TLS Output

/// Output from TLS handshake processing
public enum TLSOutput: Sendable {
    /// Handshake data to be sent at a specific encryption level
    case handshakeData(Data, level: EncryptionLevel)

    /// New keys are available for an encryption level
    case keysAvailable(KeysAvailableInfo)

    /// The handshake is complete
    case handshakeComplete(HandshakeCompleteInfo)

    /// More data is needed before further progress can be made
    case needMoreData

    /// An error occurred during TLS processing
    case error(TLSError)
}

// MARK: - Keys Available Info

/// Information about newly available keys
public struct KeysAvailableInfo: Sendable {
    /// The encryption level for these keys
    public let level: EncryptionLevel

    /// Client traffic secret
    public let clientSecret: SymmetricKey

    /// Server traffic secret
    public let serverSecret: SymmetricKey

    /// Creates keys available info
    public init(
        level: EncryptionLevel,
        clientSecret: SymmetricKey,
        serverSecret: SymmetricKey
    ) {
        self.level = level
        self.clientSecret = clientSecret
        self.serverSecret = serverSecret
    }
}

// MARK: - Handshake Complete Info

/// Information about handshake completion
public struct HandshakeCompleteInfo: Sendable {
    /// The negotiated ALPN protocol
    public let alpn: String?

    /// Whether 0-RTT was accepted
    public let zeroRTTAccepted: Bool

    /// Session resumption ticket (if any)
    public let resumptionTicket: Data?

    /// Creates handshake complete info
    public init(
        alpn: String? = nil,
        zeroRTTAccepted: Bool = false,
        resumptionTicket: Data? = nil
    ) {
        self.alpn = alpn
        self.zeroRTTAccepted = zeroRTTAccepted
        self.resumptionTicket = resumptionTicket
    }
}

// MARK: - TLS Error

/// Errors that can occur during TLS processing
public enum TLSError: Error, Sendable {
    /// Handshake failed with an alert
    case handshakeFailed(alert: UInt8, description: String)

    /// Certificate verification failed
    case certificateVerificationFailed(String)

    /// No common cipher suite
    case noCipherSuiteMatch

    /// No common ALPN protocol
    case noALPNMatch

    /// Invalid transport parameters
    case invalidTransportParameters(String)

    /// Unexpected message
    case unexpectedMessage(String)

    /// Internal error
    case internalError(String)
}
