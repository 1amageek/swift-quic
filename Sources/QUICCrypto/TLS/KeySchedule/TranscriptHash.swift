/// TLS 1.3 Transcript Hash (RFC 8446 Section 4.4.1) — QUICCrypto host adapter.
///
/// The running-hash logic lives in `QUICTLSCore` (`TLSTranscriptHashCore<C>`),
/// Embedded-clean and generic over the `CryptoProvider` seam. This adapter
/// specialises it at `C = QUICFoundationProvider` and bridges the public `Data`
/// surface so existing call sites and tests are unchanged.
///
/// For TLS 1.3, the transcript hash is:
/// ```
/// Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
/// ```

import Foundation
import Crypto
import QUICTLSCore

// MARK: - Transcript Hash

/// Maintains a running hash of handshake messages
/// Supports both SHA-256 and SHA-384 based on cipher suite
public struct TranscriptHash: Sendable {
    /// The Embedded-clean transcript hash, specialised at the host provider.
    private var core: TLSTranscriptHashCore<QUICFoundationProvider>

    /// Hash output length in bytes
    public var hashLength: Int { core.hashLength }

    // MARK: - Initialization

    /// Initialize with default SHA-256
    public init() {
        self.core = TLSTranscriptHashCore(hash: .sha256)
    }

    /// Initialize with specific cipher suite
    public init(cipherSuite: CipherSuite) {
        self.core = TLSTranscriptHashCore(hash: cipherSuite.coreCipherSuite.hash)
    }

    /// Internal init wrapping an existing core (for copy / message-hash operations)
    private init(core: TLSTranscriptHashCore<QUICFoundationProvider>) {
        self.core = core
    }

    // MARK: - Update

    /// Update the transcript with a handshake message
    /// - Parameter message: The complete handshake message (including 4-byte header)
    public mutating func update(with message: Data) {
        core.update(with: [UInt8](message))
    }

    /// Update the transcript with raw data
    /// - Parameter data: Raw data to hash
    public mutating func updateRaw(with data: Data) {
        core.updateRaw(with: [UInt8](data))
    }

    // MARK: - Hash Value

    /// Get the current transcript hash value
    /// - Returns: The hash (32 bytes for SHA-256, 48 bytes for SHA-384)
    public func currentHash() -> Data {
        Data(core.currentHash())
    }

    /// Number of messages hashed
    public var count: Int { core.messageCount }

    // MARK: - Special Operations

    /// Create a transcript hash from a message hash (for HelloRetryRequest)
    /// Per RFC 8446 Section 4.4.1:
    /// ```
    /// Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    ///     Hash(message_hash ||     /* Handshake type */
    ///          00 00 Hash.length ||  /* Uint24 length */
    ///          Hash(ClientHello1) || /* Hash */
    ///          HelloRetryRequest || ... || Mn)
    /// ```
    public static func fromMessageHash(
        clientHello1Hash: Data,
        cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256
    ) -> TranscriptHash {
        let core = TLSTranscriptHashCore<QUICFoundationProvider>.fromMessageHash(
            clientHello1Hash: [UInt8](clientHello1Hash),
            hash: cipherSuite.coreCipherSuite.hash
        )
        return TranscriptHash(core: core)
    }

    /// Create a copy of the transcript hash
    public func copy() -> TranscriptHash {
        // `core` is a value type; assigning it produces an independent copy of the
        // running hash state.
        TranscriptHash(core: core)
    }
}

// MARK: - Transcript Hash with SHA-384

/// Transcript hash using SHA-384 (for TLS_AES_256_GCM_SHA384)
public struct TranscriptHashSHA384: Sendable {
    private var core: TLSTranscriptHashCore<QUICFoundationProvider>
    private var messageCount: Int

    public init() {
        self.core = TLSTranscriptHashCore(hash: .sha384)
        self.messageCount = 0
    }

    private init(core: TLSTranscriptHashCore<QUICFoundationProvider>, messageCount: Int) {
        self.core = core
        self.messageCount = messageCount
    }

    public mutating func update(with message: Data) {
        core.update(with: [UInt8](message))
        messageCount += 1
    }

    public mutating func updateRaw(with data: Data) {
        core.updateRaw(with: [UInt8](data))
    }

    public func currentHash() -> Data {
        Data(core.currentHash())
    }

    public static var hashLength: Int { 48 }

    public var count: Int { messageCount }

    public func copy() -> TranscriptHashSHA384 {
        TranscriptHashSHA384(core: core, messageCount: messageCount)
    }
}
