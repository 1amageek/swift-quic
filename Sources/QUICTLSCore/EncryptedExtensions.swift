/// TLS 1.3 EncryptedExtensions Message (RFC 8446 Section 4.3.1)
///
/// ```
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```

import P2PCoreBytes

/// TLS 1.3 EncryptedExtensions message
public struct EncryptedExtensions: Sendable {

    /// Extensions in the message
    public let extensions: [TLSExtension]

    // MARK: - Initialization

    public init(extensions: [TLSExtension]) {
        self.extensions = extensions
    }

    // MARK: - Encoding

    /// Encodes the EncryptedExtensions content (without handshake header)
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var extensionData = [UInt8]()
        for ext in extensions {
            extensionData.append(contentsOf: try ext.encodeBytes())
        }

        var writer = ByteWriter(reservingCapacity: 2 + extensionData.count)
        try writer.wWriteVector16(extensionData)
        return writer.finishArray()
    }

    /// Encodes as a complete handshake message (with header)
    public func encodeAsHandshakeBytes() throws(TLSWireError) -> [UInt8] {
        try HandshakeMessageCodec.encode(type: .encryptedExtensions, content: try encodeBytes())
    }

    // MARK: - Decoding

    /// Decodes EncryptedExtensions from content data (without handshake header)
    public static func decode(from data: [UInt8]) throws(TLSWireError) -> EncryptedExtensions {
        var reader = ByteReader(data)
        let extensionData = try reader.wReadVector16()

        var extensions: [TLSExtension] = []
        var extReader = ByteReader(extensionData)
        while !extReader.isAtEnd {
            let ext = try TLSExtension.decode(from: &extReader)
            extensions.append(ext)
        }

        return EncryptedExtensions(extensions: extensions)
    }

    // MARK: - Extension Helpers

    /// Get ALPN extension
    public var alpn: ALPNExtension? {
        for ext in extensions {
            if case .alpn(let alpn) = ext {
                return alpn
            }
        }
        return nil
    }

    /// Get selected ALPN protocol
    public var selectedALPN: String? {
        alpn?.selectedProtocol
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

    /// Get server name extension
    public var serverName: ServerNameExtension? {
        for ext in extensions {
            if case .serverName(let serverName) = ext {
                return serverName
            }
        }
        return nil
    }
}
