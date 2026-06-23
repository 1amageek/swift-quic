/// `Data`-based convenience surface for the moved TLS handshake message types.
///
/// Each moved type's Embedded-clean core exposes `encodeBytes() throws -> [UInt8]`
/// and `decode(from: [UInt8])`. This file restores the historical non-throwing
/// `encode() -> Data` / `decode(from: Data)` API plus `Data`-accepting
/// initializers, so existing callers and tests compile unchanged.
///
/// Foundation-only adapter glue.

import Foundation
import QUICTLSCore

// MARK: - ClientHello

extension ClientHello {
    /// Creates a ClientHello from `Data` fields.
    ///
    /// The core initializer throws on an invalid random/session-id length; the
    /// pre-extraction code expressed that as a `precondition` trap, which we
    /// preserve here with a `fatalError`.
    public init(
        random: Data,
        legacySessionID: Data = Data(),
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension]
    ) {
        do {
            try self.init(
                random: [UInt8](random),
                legacySessionID: [UInt8](legacySessionID),
                cipherSuites: cipherSuites,
                extensions: extensions
            )
        } catch {
            fatalError("Invalid ClientHello: \(error)")
        }
    }

    /// Creates a ClientHello with generated random.
    public init(
        legacySessionID: Data = Data(),
        cipherSuites: [CipherSuite] = [.tls_aes_128_gcm_sha256],
        extensions: [TLSExtension]
    ) {
        let random = SecureRandom.bytes(count: TLSConstants.randomLength)
        self.init(random: random, legacySessionID: legacySessionID, cipherSuites: cipherSuites, extensions: extensions)
    }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> ClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// Find an extension by type (generic accessor).
    public func findExtension<T: TLSExtensionValue>(_ type: T.Type) -> T? {
        for ext in extensions {
            if let value = extensionValue(ext) as? T {
                return value
            }
        }
        return nil
    }
}

// MARK: - ServerHello

extension ServerHello {
    /// Creates a ServerHello from `Data` fields.
    public init(
        random: Data,
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) {
        do {
            try self.init(
                random: [UInt8](random),
                legacySessionIDEcho: [UInt8](legacySessionIDEcho),
                cipherSuite: cipherSuite,
                extensions: extensions
            )
        } catch {
            fatalError("Invalid ServerHello: \(error)")
        }
    }

    /// Creates a ServerHello with a `[UInt8]` random and `Data` session-id echo.
    ///
    /// Supports call sites that pass the `[UInt8]` HelloRetryRequest sentinel
    /// (`TLSConstants.helloRetryRequestRandom`) together with a `Data` echo.
    public init(
        random: [UInt8],
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) {
        do {
            try self.init(
                random: random,
                legacySessionIDEcho: [UInt8](legacySessionIDEcho),
                cipherSuite: cipherSuite,
                extensions: extensions
            )
        } catch {
            fatalError("Invalid ServerHello: \(error)")
        }
    }

    /// Creates a ServerHello with generated random.
    public init(
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) {
        let random = SecureRandom.bytes(count: TLSConstants.randomLength)
        self.init(random: random, legacySessionIDEcho: legacySessionIDEcho, cipherSuite: cipherSuite, extensions: extensions)
    }

    /// Creates a HelloRetryRequest with `Data` session-id echo.
    public static func helloRetryRequest(
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) -> ServerHello {
        do {
            return try helloRetryRequest(
                legacySessionIDEcho: [UInt8](legacySessionIDEcho),
                cipherSuite: cipherSuite,
                extensions: extensions
            )
        } catch {
            fatalError("Invalid HelloRetryRequest: \(error)")
        }
    }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> ServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// The 32-byte random as `Data` (the core stores it as `[UInt8]`).
    public var randomData: Data { Data(random) }

    /// Whether the random matches the HelloRetryRequest sentinel.
    /// `Data`-comparison convenience matching the historical surface.
    public var isHelloRetryRequestData: Bool {
        random == TLSConstants.helloRetryRequestRandom
    }

    /// Find an extension by type.
    public func findExtension<T: TLSExtensionValue>(_ type: T.Type) -> T? {
        for ext in extensions {
            if let value = extensionValue(ext) as? T {
                return value
            }
        }
        return nil
    }
}

// MARK: - EncryptedExtensions

extension EncryptedExtensions {
    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> EncryptedExtensions {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// QUIC transport parameters as `Data`.
    public var quicTransportParametersData: Data? { quicTransportParameters.map { Data($0) } }

    /// Find an extension by type.
    public func findExtension<T: TLSExtensionValue>(_ type: T.Type) -> T? {
        for ext in extensions {
            if let value = extensionValue(ext) as? T {
                return value
            }
        }
        return nil
    }
}

// MARK: - Certificate

extension CertificateEntry {
    /// Creates a certificate entry from `Data`.
    public init(certData: Data, extensions: [TLSExtension] = []) {
        self.init(certData: [UInt8](certData), extensions: extensions)
    }

    /// The certificate data as `Data`.
    public var certDataValue: Data { Data(certData) }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
}

extension Certificate {
    /// Creates from explicit entries with a `Data` request context.
    public init(certificateRequestContext: Data = Data(), certificateList: [CertificateEntry]) {
        self.init(
            certificateRequestContext: [UInt8](certificateRequestContext),
            certificateList: certificateList
        )
    }

    /// Creates from raw DER certificate `Data` values.
    public init(certificateRequestContext: Data = Data(), certificates: [Data]) {
        self.init(
            certificateRequestContext: [UInt8](certificateRequestContext),
            certificates: certificates.map { [UInt8]($0) }
        )
    }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> Certificate {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// The leaf certificate as `Data`.
    public var leafCertificateData: Data? { leafCertificate.map { Data($0) } }

    /// All certificate data as `Data` values.
    public var certificatesData: [Data] { certificates.map { Data($0) } }
}

// MARK: - CertificateVerify

extension CertificateVerify {
    /// Creates a CertificateVerify from a `Data` signature.
    public init(algorithm: SignatureScheme, signature: Data) {
        self.init(algorithm: algorithm, signature: [UInt8](signature))
    }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> CertificateVerify {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// The signature bytes as `Data` (the core stores it as `[UInt8]`).
    public var signatureData: Data { Data(signature) }

    /// Constructs the content to be signed, returning `Data`.
    public static func constructSignatureContent(
        transcriptHash: Data,
        isServer: Bool
    ) -> Data {
        Data(constructSignatureContentBytes(transcriptHash: [UInt8](transcriptHash), isServer: isServer))
    }
}

// MARK: - Finished / KeyUpdate

extension Finished {
    /// Creates a Finished message from `Data` verify data.
    public init(verifyData: Data) {
        self.init(verifyData: [UInt8](verifyData))
    }

    public func encode() -> Data { Data(encodeBytes()) }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data, hashLength: Int = TLSConstants.verifyDataLength) throws -> Finished {
        do { return try decode(from: [UInt8](data), hashLength: hashLength) } catch { try error.rethrowUnwrapped() }
    }

    /// The verify data as `Data` (the core stores it as `[UInt8]`).
    public var verifyDataValue: Data { Data(verifyData) }

    /// Verify against expected `Data`.
    public func verify(expected: Data) -> Bool {
        verify(expected: [UInt8](expected))
    }
}

extension KeyUpdate {
    public func encode() -> Data { Data(encodeBytes()) }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> KeyUpdate {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - CertificateRequest

extension CertificateRequest {
    /// Creates a CertificateRequest from a `Data` request context.
    public init(certificateRequestContext: Data, extensions: [TLSExtension] = []) {
        self.init(
            certificateRequestContext: [UInt8](certificateRequestContext),
            extensions: extensions
        )
    }

    /// Creates a CertificateRequest with default signature algorithms and a `Data` context.
    public static func withDefaultSignatureAlgorithms(
        certificateRequestContext: Data
    ) -> CertificateRequest {
        withDefaultSignatureAlgorithms(certificateRequestContext: [UInt8](certificateRequestContext))
    }

    /// The request context as `Data` (the core stores it as `[UInt8]`).
    public var certificateRequestContextData: Data { Data(certificateRequestContext) }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { tlsEncodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> CertificateRequest {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - NewSessionTicket

extension NewSessionTicket {
    /// Creates a NewSessionTicket from `Data` fields.
    public init(
        ticketLifetime: UInt32,
        ticketAgeAdd: UInt32,
        ticketNonce: Data,
        ticket: Data,
        extensions: [TLSExtension] = []
    ) {
        self.init(
            ticketLifetime: ticketLifetime,
            ticketAgeAdd: ticketAgeAdd,
            ticketNonce: [UInt8](ticketNonce),
            ticket: [UInt8](ticket),
            extensions: extensions
        )
    }

    /// The ticket value as `Data` (the core stores it as `[UInt8]`).
    public var ticketData: Data { Data(ticket) }

    /// The ticket nonce as `Data` (the core stores it as `[UInt8]`).
    public var ticketNonceData: Data { Data(ticketNonce) }

    public func encode() -> Data { tlsEncodeData { try encodeBytes() } }
    public func encodeMessage() -> Data { tlsEncodeData { try encodeMessageBytes() } }
    public static func decode(from data: Data) throws -> NewSessionTicket {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension EarlyDataIndication {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decode(from data: Data) throws -> EarlyDataIndication {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - Alert

extension TLSAlert {
    /// Encode the alert as 2 bytes of `Data`.
    public func encode() -> Data { Data(encodeBytes()) }

    /// Encode as a complete TLS record (`Data`).
    public func encodeAsRecord() -> Data { Data(encodeAsRecordBytes()) }

    /// Decode an alert from `Data`.
    public static func decode(from data: Data) throws -> TLSAlert {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - EndOfEarlyData

extension EndOfEarlyData {
    public func encode() -> Data { Data(encodeBytes()) }
    public func encodeMessage() -> Data { tlsEncodeData { try encodeMessageBytes() } }
    public static func decode(from data: Data) throws -> EndOfEarlyData {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}
