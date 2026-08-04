/// Transport-facing results emitted by a QUIC TLS provider.

import Foundation
import Crypto
import QUICCore
import TLSWireCore

/// Output from TLS handshake processing.
public enum TLSOutput: Sendable {
    case handshakeData(Data, level: EncryptionLevel)
    case keysAvailable(KeysAvailableInfo)
    case handshakeComplete(HandshakeCompleteInfo)
    case needMoreData
    case error(TLSError)
    case alert(TLSAlert)
    case newSessionTicket(NewSessionTicketInfo)
}

/// Information about a received TLS 1.3 NewSessionTicket.
public struct NewSessionTicketInfo: Sendable {
    public let ticket: NewSessionTicket
    public let resumptionMasterSecret: SymmetricKey
    public let cipherSuite: CipherSuite
    public let alpn: String?

    public init(
        ticket: NewSessionTicket,
        resumptionMasterSecret: SymmetricKey,
        cipherSuite: CipherSuite,
        alpn: String? = nil
    ) {
        self.ticket = ticket
        self.resumptionMasterSecret = resumptionMasterSecret
        self.cipherSuite = cipherSuite
        self.alpn = alpn
    }
}

/// Secrets exported by TLS for QUIC packet protection.
public struct KeysAvailableInfo: Sendable {
    public let level: EncryptionLevel
    public let clientSecret: SymmetricKey?
    public let serverSecret: SymmetricKey?
    public let cipherSuite: QUICCipherSuite

    public init(
        level: EncryptionLevel,
        clientSecret: SymmetricKey?,
        serverSecret: SymmetricKey?,
        cipherSuite: QUICCipherSuite = .aes128GcmSha256
    ) {
        self.level = level
        self.clientSecret = clientSecret
        self.serverSecret = serverSecret
        self.cipherSuite = cipherSuite
    }
}

/// Information emitted when the TLS handshake reaches the QUIC established state.
public struct HandshakeCompleteInfo: Sendable {
    public let alpn: String?
    public let zeroRTTAccepted: Bool
    public let resumptionTicket: Data?

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

/// Typed failures at the QUIC/TLS adapter boundary.
public enum TLSError: Error, Sendable {
    case handshakeFailed(alert: UInt8, description: String)
    case certificateVerificationFailed(String)
    case noCipherSuiteMatch
    case noALPNMatch
    case invalidTransportParameters(String)
    case unexpectedMessage(String)
    case internalError(String)

    public var toAlert: TLSAlert {
        switch self {
        case .handshakeFailed(let alert, _):
            let description = AlertDescription(rawValue: alert) ?? .handshakeFailure
            return TLSAlert(description: description)
        case .certificateVerificationFailed:
            return TLSAlert(description: .badCertificate)
        case .noCipherSuiteMatch:
            return TLSAlert(description: .handshakeFailure)
        case .noALPNMatch:
            return TLSAlert(description: .noApplicationProtocol)
        case .invalidTransportParameters:
            return TLSAlert(description: .illegalParameter)
        case .unexpectedMessage:
            return TLSAlert(description: .unexpectedMessage)
        case .internalError:
            return TLSAlert(description: .internalError)
        }
    }
}
