/// TLS 1.3 ClientHello Message (RFC 8446 Section 4.1.2)
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// } ClientHello;
/// ```

import P2PCoreBytes

/// TLS 1.3 ClientHello message
public struct ClientHello: Sendable {

    /// 32 bytes of random data
    public let random: [UInt8]

    /// Legacy session ID (can be non-empty for middlebox compatibility)
    public let legacySessionID: [UInt8]

    /// Cipher suites in preference order
    public let cipherSuites: [CipherSuite]

    /// Extensions (order matters for some extensions)
    public let extensions: [TLSExtension]

    // MARK: - Initialization

    /// Creates a ClientHello with the specified parameters.
    ///
    /// - Throws: ``TLSWireError/invalidFormat(_:)`` if `random` is not 32 bytes
    ///   or `legacySessionID` exceeds the max length. (The `QUICCrypto` adapter's
    ///   `Data` initializer expresses these as the historical `precondition` trap.)
    public init(
        random: [UInt8],
        legacySessionID: [UInt8] = [],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension]
    ) throws(TLSWireError) {
        guard random.count == TLSConstants.randomLength else {
            throw TLSWireError.invalidFormat("ClientHello random must be \(TLSConstants.randomLength) bytes, got \(random.count)")
        }
        guard legacySessionID.count <= TLSConstants.sessionIDMaxLength else {
            throw TLSWireError.invalidFormat("ClientHello session ID too long: \(legacySessionID.count) bytes (max \(TLSConstants.sessionIDMaxLength))")
        }
        self.random = random
        self.legacySessionID = legacySessionID
        self.cipherSuites = cipherSuites
        self.extensions = extensions
    }

    // MARK: - Encoding

    /// Encodes the ClientHello content (without handshake header)
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 512)

        // legacy_version (2 bytes) - always 0x0303 for TLS 1.3
        writer.writeUInt16(TLSConstants.legacyVersion)

        // random (32 bytes)
        writer.writeBytes(random)

        // legacy_session_id (variable, 1-byte length)
        try writer.wWriteVector8(legacySessionID)

        // cipher_suites (variable, 2-byte length)
        var cipherSuiteData = [UInt8]()
        cipherSuiteData.reserveCapacity(cipherSuites.count * 2)
        for suite in cipherSuites {
            cipherSuiteData.append(UInt8((suite.rawValue >> 8) & 0xFF))
            cipherSuiteData.append(UInt8(suite.rawValue & 0xFF))
        }
        try writer.wWriteVector16(cipherSuiteData)

        // legacy_compression_methods (variable, 1-byte length) - must be [0x00]
        try writer.wWriteVector8([0x00])

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
        try HandshakeMessageCodec.encode(type: .clientHello, content: try encodeBytes())
    }

    // MARK: - Decoding

    /// Decodes a ClientHello from content data (without handshake header)
    public static func decode(from data: [UInt8]) throws(TLSWireError) -> ClientHello {
        var reader = ByteReader(data)

        // legacy_version
        let legacyVersion = try reader.wReadUInt16()
        guard legacyVersion == TLSConstants.legacyVersion else {
            throw TLSWireError.unsupportedVersion(legacyVersion)
        }

        // random
        let random = try reader.wReadBytes(TLSConstants.randomLength)

        // legacy_session_id
        let legacySessionID = try reader.wReadVector8()

        // cipher_suites
        let cipherSuiteData = try reader.wReadVector16()
        guard cipherSuiteData.count >= 2 && cipherSuiteData.count % 2 == 0 else {
            throw TLSWireError.invalidFormat("Invalid cipher suite length")
        }
        var cipherSuites: [CipherSuite] = []
        var csReader = ByteReader(cipherSuiteData)
        while !csReader.isAtEnd {
            let value = try csReader.wReadUInt16()
            if let suite = CipherSuite(rawValue: value) {
                cipherSuites.append(suite)
            }
            // Unknown cipher suites are ignored
        }

        // legacy_compression_methods
        let compressionMethods = try reader.wReadVector8()
        guard compressionMethods.count >= 1 && compressionMethods[0] == 0x00 else {
            throw TLSWireError.invalidFormat("Invalid compression methods")
        }

        // extensions
        let extensionData = try reader.wReadVector16()
        var extensions: [TLSExtension] = []
        var extReader = ByteReader(extensionData)
        while !extReader.isAtEnd {
            let ext = try TLSExtension.decode(from: &extReader)
            extensions.append(ext)
        }

        return try ClientHello(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensions
        )
    }

    // MARK: - Extension Helpers

    /// Get key share extension
    public var keyShare: KeyShareClientHello? {
        for ext in extensions {
            if case .keyShare(let wrapper) = ext {
                if case .clientHello(let keyShare) = wrapper {
                    return keyShare
                }
            }
        }
        return nil
    }

    /// Get supported versions extension
    public var supportedVersions: SupportedVersionsClientHello? {
        for ext in extensions {
            if case .supportedVersions(let wrapper) = ext {
                if case .clientHello(let versions) = wrapper {
                    return versions
                }
            }
        }
        return nil
    }

    /// Get ALPN extension
    public var alpn: ALPNExtension? {
        for ext in extensions {
            if case .alpn(let alpn) = ext {
                return alpn
            }
        }
        return nil
    }

    /// Get supported groups extension
    public var supportedGroups: SupportedGroupsExtension? {
        for ext in extensions {
            if case .supportedGroups(let groups) = ext {
                return groups
            }
        }
        return nil
    }

    /// Get QUIC transport parameters
    public var quicTransportParameters: [UInt8]? {
        for ext in extensions {
            if case .quicTransportParameters(let data) = ext {
                return data
            }
        }
        return nil
    }

    /// Get pre-shared key extension
    public var preSharedKey: OfferedPsks? {
        for ext in extensions {
            if case .preSharedKey(.clientHello(let offered)) = ext {
                return offered
            }
        }
        return nil
    }

    /// Get early_data extension
    public var earlyData: Bool {
        for ext in extensions {
            if case .earlyData = ext {
                return true
            }
        }
        return false
    }
}
