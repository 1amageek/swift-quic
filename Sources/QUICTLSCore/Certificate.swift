/// TLS 1.3 Certificate Message (RFC 8446 Section 4.4.2)
///
/// ```
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct {
///     select (certificate_type) {
///         case RawPublicKey:
///             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
///         case X509:
///             opaque cert_data<1..2^24-1>;
///     };
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
/// ```

import P2PCoreBytes

// MARK: - Certificate Entry

/// A certificate entry in the Certificate message
public struct CertificateEntry: Sendable {
    /// The certificate data (DER-encoded X.509)
    public let certData: [UInt8]

    /// Extensions for this certificate (e.g., OCSP status)
    public let extensions: [TLSExtension]

    public init(certData: [UInt8], extensions: [TLSExtension] = []) {
        self.certData = certData
        self.extensions = extensions
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var extensionData = [UInt8]()
        for ext in extensions {
            extensionData.append(contentsOf: try ext.encodeBytes())
        }

        var writer = ByteWriter(reservingCapacity: 3 + certData.count + 2 + extensionData.count)
        // cert_data<1..2^24-1>
        try writer.wWriteVector24(certData)
        // extensions<0..2^16-1>
        try writer.wWriteVector16(extensionData)
        return writer.finishArray()
    }

    public static func decode(from reader: inout ByteReader) throws(TLSWireError) -> CertificateEntry {
        let certData = try reader.wReadVector24()
        // RFC 8446 §4.4.2: cert_data is `<1..2^24-1>`. A zero-length entry is
        // malformed — reject it at the TLS layer. (Otherwise an empty leaf yields a
        // non-empty certificate_list that passes the driver's `!isEmpty` guard and is
        // only caught later by the RPK verifier; fail closed here instead.)
        guard !certData.isEmpty else {
            throw .invalidFormat("CertificateEntry cert_data must be non-empty (RFC 8446 §4.4.2)")
        }
        let extensionData = try reader.wReadVector16()

        var extensions: [TLSExtension] = []
        var extReader = ByteReader(extensionData)
        while !extReader.isAtEnd {
            let ext = try TLSExtension.decode(from: &extReader)
            extensions.append(ext)
        }

        return CertificateEntry(certData: certData, extensions: extensions)
    }
}

// MARK: - Certificate Message

/// TLS 1.3 Certificate message
public struct Certificate: Sendable {

    /// The certificate request context (empty for server certificates)
    public let certificateRequestContext: [UInt8]

    /// The certificate chain (leaf first)
    public let certificateList: [CertificateEntry]

    // MARK: - Initialization

    public init(certificateRequestContext: [UInt8] = [], certificateList: [CertificateEntry]) {
        self.certificateRequestContext = certificateRequestContext
        self.certificateList = certificateList
    }

    /// Create from raw certificate data (DER-encoded)
    public init(certificateRequestContext: [UInt8] = [], certificates: [[UInt8]]) {
        self.certificateRequestContext = certificateRequestContext
        self.certificateList = certificates.map { CertificateEntry(certData: $0) }
    }

    // MARK: - Encoding

    /// Encodes the Certificate content (without handshake header)
    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var certListData = [UInt8]()
        for entry in certificateList {
            certListData.append(contentsOf: try entry.encodeBytes())
        }

        var writer = ByteWriter(reservingCapacity: 1 + certificateRequestContext.count + 3 + certListData.count)
        // certificate_request_context<0..2^8-1>
        try writer.wWriteVector8(certificateRequestContext)
        // certificate_list<0..2^24-1>
        try writer.wWriteVector24(certListData)
        return writer.finishArray()
    }

    /// Encodes as a complete handshake message (with header)
    public func encodeAsHandshakeBytes() throws(TLSWireError) -> [UInt8] {
        try HandshakeMessageCodec.encode(type: .certificate, content: try encodeBytes())
    }

    // MARK: - Decoding

    /// Decodes Certificate from content data (without handshake header)
    public static func decode(from data: [UInt8]) throws(TLSWireError) -> Certificate {
        var reader = ByteReader(data)

        // certificate_request_context
        let certificateRequestContext = try reader.wReadVector8()

        // certificate_list
        let certListData = try reader.wReadVector24()
        var certificateList: [CertificateEntry] = []
        var listReader = ByteReader(certListData)
        while !listReader.isAtEnd {
            certificateList.append(try CertificateEntry.decode(from: &listReader))
        }

        return Certificate(
            certificateRequestContext: certificateRequestContext,
            certificateList: certificateList
        )
    }

    // MARK: - Helpers

    /// Get the leaf (end-entity) certificate
    public var leafCertificate: [UInt8]? {
        certificateList.first?.certData
    }

    /// Get all certificate data (without extensions)
    public var certificates: [[UInt8]] {
        certificateList.map { $0.certData }
    }

    /// Whether the certificate chain is empty
    public var isEmpty: Bool {
        certificateList.isEmpty
    }
}
