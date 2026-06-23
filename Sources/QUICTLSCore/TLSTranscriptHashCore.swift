/// TLS 1.3 transcript hash (RFC 8446 §4.4.1), Embedded-clean and generic over
/// `C: CryptoProvider`.
///
/// Maintains a running hash of all handshake messages:
/// `Transcript-Hash(M1, ..., Mn) = Hash(M1 || ... || Mn)`. SHA-256 or SHA-384 is
/// selected per cipher suite. The hash state is held as a value-type `C.SHA256` /
/// `C.SHA384` over the `HashFunction` seam; `currentHash()` finalizes a copy so the
/// running state is preserved for further updates.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto. `[UInt8]` in/out.
import P2PCoreBytes
import P2PCoreCrypto

/// An incremental TLS 1.3 transcript hash over the crypto seam.
public struct TLSTranscriptHashCore<C: CryptoProvider>: Sendable {

    /// The hash function variant, holding the running state.
    private enum Hasher: Sendable {
        case sha256(C.SHA256)
        case sha384(C.SHA384)
    }

    private var hasher: Hasher

    /// Number of messages fed into the transcript.
    public private(set) var messageCount: Int

    /// Hash output length in bytes (32 for SHA-256, 48 for SHA-384).
    public let hashLength: Int

    // MARK: - Initialization

    /// Creates an empty transcript for the given hash algorithm.
    public init(hash: TLSHashAlgorithm) {
        switch hash {
        case .sha256:
            self.hasher = .sha256(C.SHA256())
            self.hashLength = C.SHA256.digestLength
        case .sha384:
            self.hasher = .sha384(C.SHA384())
            self.hashLength = C.SHA384.digestLength
        }
        self.messageCount = 0
    }

    // MARK: - Update

    /// Feeds a complete handshake message (including its 4-byte header) into the
    /// transcript and increments the message count.
    public mutating func update(with message: [UInt8]) {
        appendBytes(message)
        messageCount += 1
    }

    /// Feeds raw bytes into the transcript without incrementing the message count.
    public mutating func updateRaw(with data: [UInt8]) {
        appendBytes(data)
    }

    private mutating func appendBytes(_ bytes: [UInt8]) {
        switch hasher {
        case .sha256(var h):
            h.update(bytes.span)
            hasher = .sha256(h)
        case .sha384(var h):
            h.update(bytes.span)
            hasher = .sha384(h)
        }
    }

    // MARK: - Hash Value

    /// Returns the current transcript hash without disturbing the running state.
    ///
    /// The `HashFunction.finalize()` seam is `consuming`, so a copy of the running
    /// state is finalized and the original is preserved for further updates.
    public func currentHash() -> [UInt8] {
        switch hasher {
        case .sha256(let h):
            let copy = h
            return copy.finalize()
        case .sha384(let h):
            let copy = h
            return copy.finalize()
        }
    }

    // MARK: - HelloRetryRequest synthetic message

    /// Builds the synthetic `message_hash` handshake message that replaces the first
    /// ClientHello when a HelloRetryRequest is sent (RFC 8446 §4.4.1):
    /// ```
    /// message_hash(254) || 00 00 Hash.length || Hash(ClientHello1)
    /// ```
    /// The returned transcript has consumed exactly this synthetic message.
    public static func fromMessageHash(
        clientHello1Hash: [UInt8],
        hash: TLSHashAlgorithm
    ) -> TLSTranscriptHashCore {
        var transcript = TLSTranscriptHashCore(hash: hash)
        var writer = ByteWriter()
        writer.writeUInt8(254) // HandshakeType.message_hash
        writer.writeUInt8(0x00) // length high
        writer.writeUInt8(0x00) // length mid
        writer.writeUInt8(UInt8(truncatingIfNeeded: clientHello1Hash.count)) // length low
        writer.writeBytes(clientHello1Hash)
        transcript.update(with: writer.finishArray())
        return transcript
    }
}
