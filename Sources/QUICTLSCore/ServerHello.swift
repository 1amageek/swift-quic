/// TLS 1.3 ServerHello Message (RFC 8446 Section 4.1.3)
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```

import P2PCoreBytes

/// TLS 1.3 ServerHello message
public struct ServerHello: Sendable {

    /// 32 bytes of random data
    public let random: [UInt8]

    /// Legacy session ID echo (must match ClientHello)
    public let legacySessionIDEcho: [UInt8]

    /// Selected cipher suite
    public let cipherSuite: CipherSuite

    /// Extensions (must contain key_share and supported_versions)
    public let extensions: [TLSExtension]

    // MARK: - Computed Properties

    /// Whether this is a HelloRetryRequest
    public var isHelloRetryRequest: Bool {
        random == TLSConstants.helloRetryRequestRandom
    }

    // MARK: - Initialization

    /// Creates a ServerHello with the specified parameters.
    ///
    /// - Throws: ``TLSWireError/invalidFormat(_:)`` if `random` is not 32 bytes.
    ///   (The `QUICCrypto` adapter's `Data` initializer expresses this as the
    ///   historical `precondition` trap.)
    public init(
        random: [UInt8],
        legacySessionIDEcho: [UInt8],
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) throws(TLSWireError) {
        guard random.count == TLSConstants.randomLength else {
            throw TLSWireError.invalidFormat("ServerHello random must be \(TLSConstants.randomLength) bytes, got \(random.count)")
        }
        self.random = random
        self.legacySessionIDEcho = legacySessionIDEcho
        self.cipherSuite = cipherSuite
        self.extensions = extensions
    }

    /// Creates a HelloRetryRequest
    public static func helloRetryRequest(
        legacySessionIDEcho: [UInt8],
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) throws(TLSWireError) -> ServerHello {
        try ServerHello(
            random: TLSConstants.helloRetryRequestRandom,
            legacySessionIDEcho: legacySessionIDEcho,
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }

    // MARK: - Encoding

    /// Encodes the ServerHello content (without handshake header)
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 128)

        // legacy_version (2 bytes) - always 0x0303 for TLS 1.3
        writer.writeUInt16(TLSConstants.legacyVersion)

        // random (32 bytes)
        writer.writeBytes(random)

        // legacy_session_id_echo (variable, 1-byte length)
        try writer.wWriteVector8(legacySessionIDEcho)

        // cipher_suite (2 bytes)
        writer.writeUInt16(cipherSuite.rawValue)

        // legacy_compression_method (1 byte) - must be 0x00
        writer.writeUInt8(0x00)

        // extensions (variable, 2-byte length)
        var extensionData = [UInt8]()
        for ext in extensions {
            extensionData.append(contentsOf: try ext.encodeBytes())
        }
        try writer.wWriteVector16(extensionData)

        return writer.finishArray()
    }

    /// Encodes as a complete handshake message (with header)
    public func encodeAsHandshakeBytes() throws(TLSWireError) -> [UInt8] {
        try HandshakeMessageCodec.encode(type: .serverHello, content: try encodeBytes())
    }

    // MARK: - Decoding

    /// Decodes a ServerHello from content data (without handshake header)
    public static func decode(from data: [UInt8]) throws(TLSWireError) -> ServerHello {
        var reader = ByteReader(data)

        // legacy_version
        let legacyVersion = try reader.wReadUInt16()
        guard legacyVersion == TLSConstants.legacyVersion else {
            throw TLSWireError.unsupportedVersion(legacyVersion)
        }

        // random
        let random = try reader.wReadBytes(TLSConstants.randomLength)

        // legacy_session_id_echo
        let legacySessionIDEcho = try reader.wReadVector8()

        // cipher_suite
        let cipherSuiteValue = try reader.wReadUInt16()
        guard let cipherSuite = CipherSuite(rawValue: cipherSuiteValue) else {
            throw TLSWireError.invalidFormat("Unknown cipher suite: \(cipherSuiteValue)")
        }

        // legacy_compression_method
        let compressionMethod = try reader.wReadUInt8()
        guard compressionMethod == 0x00 else {
            throw TLSWireError.invalidFormat("Invalid compression method: \(compressionMethod)")
        }

        // extensions
        let extensionData = try reader.wReadVector16()
        var extensions: [TLSExtension] = []
        var extReader = ByteReader(extensionData)
        while !extReader.isAtEnd {
            let ext = try TLSExtension.decode(from: &extReader)
            extensions.append(ext)
        }

        return try ServerHello(
            random: random,
            legacySessionIDEcho: legacySessionIDEcho,
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }

    // MARK: - Extension Helpers

    /// Get key share extension
    public var keyShare: KeyShareServerHello? {
        for ext in extensions {
            if case .keyShare(let wrapper) = ext {
                if case .serverHello(let keyShare) = wrapper {
                    return keyShare
                }
            }
        }
        return nil
    }

    /// Get supported versions extension
    public var supportedVersions: SupportedVersionsServerHello? {
        for ext in extensions {
            if case .supportedVersions(let wrapper) = ext {
                if case .serverHello(let versions) = wrapper {
                    return versions
                }
            }
        }
        return nil
    }

    /// Get the requested key share group from HelloRetryRequest
    /// Returns nil if this is not an HRR or if the key_share extension is missing
    public var helloRetryRequestSelectedGroup: NamedGroup? {
        guard isHelloRetryRequest else { return nil }

        for ext in extensions {
            if case .keyShare(let wrapper) = ext {
                // In HRR, key_share contains just a NamedGroup (2 bytes)
                // The current decoding might try to decode it as KeyShareServerHello
                // which would fail if the data is only 2 bytes
                if case .helloRetryRequest(let hrr) = wrapper {
                    return hrr.selectedGroup
                }
                // Fallback: try to extract from serverHello if it somehow decoded
                if case .serverHello(let keyShare) = wrapper {
                    return keyShare.serverShare.group
                }
            }
        }
        return nil
    }
}
