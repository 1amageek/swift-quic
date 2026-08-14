/// QUIC packet parse / serialize — Embedded-clean core (RFC 9000 §12/§17,
/// RFC 9001 §5).
///
/// `PacketParsingCore` performs the full packet codec over `[UInt8]`:
/// - serialize: frames -> payload -> AEAD seal -> header protection (apply),
/// - parse: remove header protection -> decode packet number -> AEAD open ->
///   decode frames.
///
/// Crypto is supplied as the closed-suite ``SuiteProtector`` owner, so this core
/// carries no packet-opener/sealer existential and no `swift-crypto` dependency.
///
/// The stateful pieces stay engine-side: the connection's per-level
/// `SuiteProtector` selection, packet-number-space tracking, ACK tracking, key
/// phase commitment (RFC 9001 §6.3), the `Mutex`, and the async I/O loop. The
/// engine passes a `SuiteProtector` (and, for 1-RTT, a phase-aware selector
/// closure) in and drives this parser.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`;
/// typed throws (``PacketParsingError``); no silent fallback — a decrypt failure
/// or malformed packet throws, never a garbage/empty return.

import NetworkingCore
import QUICWire
import QUICPacketProtectionCore

/// Error thrown by ``PacketParsingCore``.
public enum PacketParsingError: Error, Sendable {
    /// Insufficient data to parse the packet.
    case insufficientData
    /// The packet structure violated its RFC 9000 encoding rules.
    case invalidPacketFormat(String)
    /// AEAD open/seal or header protection failed (RFC 9001 §5).
    case protection(PacketProtectionError)
    /// A protected packet reached the parser with no protector / opener to open
    /// it (e.g. keys for that level/phase are not installed). Fails closed —
    /// never a silent fallback.
    case noProtector
    /// A frame in the decrypted payload was malformed.
    case frame(FrameCodecError)
    /// The packet header failed post-unprotect validation (reserved bits, …).
    case headerValidation(HeaderValidationError)
    /// A length/offset value from untrusted data was out of range.
    case conversion(ConversionError)
    /// The serialized packet exceeded the caller's maximum size.
    case packetTooLarge(size: Int, maxSize: Int)
}

/// A fully parsed and decrypted QUIC packet (core value form).
public struct ParsedPacketCore: Sendable {
    /// The validated packet header.
    public let header: PacketHeader
    /// The decoded full packet number.
    public let packetNumber: UInt64
    /// The decrypted frames.
    public let frames: [Frame]
    /// The encryption level (packet number space).
    public let encryptionLevel: EncryptionLevel
    /// The packet size in bytes.
    public let packetSize: Int
    /// The 1-RTT Key Phase bit (RFC 9001 §6), or `nil` for long-header packets.
    public let keyPhase: UInt8?

    public init(
        header: PacketHeader,
        packetNumber: UInt64,
        frames: [Frame],
        encryptionLevel: EncryptionLevel,
        packetSize: Int,
        keyPhase: UInt8? = nil
    ) {
        self.header = header
        self.packetNumber = packetNumber
        self.frames = frames
        self.encryptionLevel = encryptionLevel
        self.packetSize = packetSize
        self.keyPhase = keyPhase
    }
}

/// The pure packet parse/serialize core.
public enum PacketParsingCore {

    /// AEAD authentication tag size (16 bytes for AES-GCM / ChaCha20-Poly1305).
    public static let aeadTagSize = 16

    /// Minimum UDP datagram size for Initial packets (RFC 9000 §14.1).
    public static let initialPacketMinSize = 1200

    /// Default MTU for QUIC (minimum guaranteed).
    public static let defaultMTU = 1200

    private static let frameCodec = StandardFrameCodec()

    // MARK: - Serialize

    /// Serializes and protects a Long Header packet (RFC 9000 §17.2, RFC 9001 §5).
    ///
    /// Mirrors the historical `PacketEncoder.encodeLongHeaderPacket` byte-for-byte:
    /// frames -> payload (+Initial padding) -> Length field -> AEAD seal (AAD =
    /// header || unprotected PN) -> apply header protection.
    public static func serializeLongHeaderPacket(
        frames: [Frame],
        header: LongHeader,
        packetNumber: UInt64,
        protector: SuiteProtector,
        maxPacketSize: Int = defaultMTU,
        padToMinimum: Bool = true
    ) throws(PacketParsingError) -> [UInt8] {
        var header = header
        header.packetNumber = packetNumber

        // Encode frames to payload.
        var payload: [UInt8]
        do { payload = try frameCodec.encodeFrames(frames) } catch { throw .frame(error) }

        // RFC 9000 §14.1: Initial packets MUST be padded to at least 1200 bytes.
        if padToMinimum && header.packetType == .initial {
            let estimatedHeaderSize = estimateLongHeaderSize(header)
            let currentSize = estimatedHeaderSize + header.packetNumberLength + payload.count + aeadTagSize
            if currentSize < initialPacketMinSize {
                let paddingNeeded = initialPacketMinSize - currentSize
                payload.append(contentsOf: repeatElement(UInt8(0), count: paddingNeeded))
            }
        }

        // Length field value = PN length + payload length + AEAD tag.
        let lengthValue = header.packetNumberLength + payload.count + aeadTagSize

        // Build header up to (and including) the Length field.
        let headerWithLength = try buildLongHeaderWithLength(header, length: UInt64(lengthValue))

        // Build packet-number bytes.
        let pnBytes = encodePacketNumberBytes(packetNumber, length: header.packetNumberLength)

        // RFC 9001 §5.3: AAD = header up to and including the unprotected PN.
        var aad = headerWithLength
        aad.append(contentsOf: pnBytes)

        // Encrypt payload.
        let ciphertext: [UInt8]
        do {
            ciphertext = try protector.seal(payload.span, packetNumber: packetNumber, header: aad.span)
        } catch {
            throw .protection(error)
        }

        // Combine header + PN + ciphertext (before header protection).
        var packet = headerWithLength
        packet.append(contentsOf: pnBytes)
        packet.append(contentsOf: ciphertext)

        // Apply header protection. Sample starts 4 bytes after the PN offset.
        let pnOffset = headerWithLength.count
        let sampleOffset = pnOffset + 4
        guard packet.count >= sampleOffset + 16 else {
            throw .invalidPacketFormat("Packet too short for header protection sample")
        }
        let protectedFirstByte: UInt8
        let protectedPN: [UInt8]
        do {
            (protectedFirstByte, protectedPN) = try protectHeader(
                packet: packet,
                sampleOffset: sampleOffset,
                firstByte: packet[0],
                packetNumberBytes: pnBytes,
                protector: protector
            )
        } catch {
            throw .protection(error)
        }

        packet[0] = protectedFirstByte
        replaceSubrange(&packet, at: pnOffset, count: header.packetNumberLength, with: protectedPN)

        guard packet.count <= maxPacketSize else {
            throw .packetTooLarge(size: packet.count, maxSize: maxPacketSize)
        }
        return packet
    }

    /// Serializes and protects a Short Header (1-RTT) packet (RFC 9000 §17.3,
    /// RFC 9001 §5). Mirrors `PacketEncoder.encodeShortHeaderPacket` byte-for-byte.
    public static func serializeShortHeaderPacket(
        frames: [Frame],
        header: ShortHeader,
        packetNumber: UInt64,
        protector: SuiteProtector,
        headerProtectionProtector: SuiteProtector? = nil,
        maxPacketSize: Int = defaultMTU
    ) throws(PacketParsingError) -> [UInt8] {
        var header = header
        header.packetNumber = packetNumber

        let payload: [UInt8]
        do { payload = try frameCodec.encodeFrames(frames) } catch { throw .frame(error) }

        // Unprotected header = first byte + DCID.
        var unprotectedHeader: [UInt8] = []
        unprotectedHeader.append(header.firstByte)
        unprotectedHeader.append(contentsOf: header.destinationConnectionID.bytes)

        let pnBytes = encodePacketNumberBytes(packetNumber, length: header.packetNumberLength)

        var aad = unprotectedHeader
        aad.append(contentsOf: pnBytes)

        let ciphertext: [UInt8]
        do {
            ciphertext = try protector.seal(payload.span, packetNumber: packetNumber, header: aad.span)
        } catch {
            throw .protection(error)
        }

        var packet = unprotectedHeader
        packet.append(contentsOf: pnBytes)
        packet.append(contentsOf: ciphertext)

        let pnOffset = unprotectedHeader.count
        let sampleOffset = pnOffset + 4
        guard packet.count >= sampleOffset + 16 else {
            throw .invalidPacketFormat("Packet too short for header protection sample")
        }
        let protectedFirstByte: UInt8
        let protectedPN: [UInt8]
        do {
            (protectedFirstByte, protectedPN) = try protectHeader(
                packet: packet,
                sampleOffset: sampleOffset,
                firstByte: packet[0],
                packetNumberBytes: pnBytes,
                protector: headerProtectionProtector ?? protector
            )
        } catch {
            throw .protection(error)
        }

        packet[0] = protectedFirstByte
        replaceSubrange(&packet, at: pnOffset, count: header.packetNumberLength, with: protectedPN)

        guard packet.count <= maxPacketSize else {
            throw .packetTooLarge(size: packet.count, maxSize: maxPacketSize)
        }
        return packet
    }

    // MARK: - Parse

    /// Parses and decrypts a Long Header packet (RFC 9000 §17.2, RFC 9001 §5).
    ///
    /// Mirrors `PacketDecoder.decodeLongHeaderPacket` byte-for-byte. `protector`
    /// is `nil` only for unprotected packets (Version Negotiation / Retry); a
    /// protected packet with no protector throws ``PacketParsingError`` rather
    /// than returning garbage.
    public static func parseLongHeaderPacket(
        bytes: Span<UInt8>,
        protector: SuiteProtector?,
        largestPN: UInt64
    ) throws(PacketParsingError) -> ParsedPacketCore {
        // Step 1: Parse the protected header.
        let protectedHeader: ProtectedLongHeader
        let headerLength: Int
        do {
            (protectedHeader, headerLength) = try ProtectedLongHeader.parse(from: bytes)
        } catch ProtectedLongHeader.ParseError.insufficientData {
            throw .insufficientData
        } catch {
            throw .invalidPacketFormat("Malformed long header")
        }

        // Unprotected special packets (Version Negotiation / Retry).
        if protectedHeader.packetType == .versionNegotiation || protectedHeader.packetType == .retry {
            let header = LongHeader(
                parsedFirstByte: protectedHeader.protectedFirstByte,
                version: protectedHeader.version,
                destinationConnectionID: protectedHeader.destinationConnectionID,
                sourceConnectionID: protectedHeader.sourceConnectionID,
                token: protectedHeader.token,
                retryIntegrityTag: protectedHeader.retryIntegrityTag,
                length: protectedHeader.length,
                packetNumber: 0,
                packetNumberLength: 0
            )
            return ParsedPacketCore(
                header: .long(header),
                packetNumber: 0,
                frames: [],
                encryptionLevel: .initial,
                packetSize: bytes.count
            )
        }

        guard let protector = protector else {
            throw .noProtector
        }

        // Step 2: Offsets + sample.
        let pnOffset = headerLength
        let sampleOffset = pnOffset + 4
        guard bytes.count >= sampleOffset + 16 else {
            throw .insufficientData
        }
        // RFC 9001 §5.4.1: always read 4 PN bytes before removing header protection.
        let protectedPNBytesEnd = min(pnOffset + 4, bytes.count)
        let protectedPNBytes = materialize(bytes.extracting(pnOffset..<protectedPNBytesEnd))
        let sample = bytes.extracting(sampleOffset..<(sampleOffset + 16))

        // Step 3: Remove header protection.
        let unprotectedFirstByte: UInt8
        let unprotectedPNBytes: [UInt8]
        do {
            (unprotectedFirstByte, unprotectedPNBytes) = try protector.removeHeaderProtection(
                sample: sample, firstByte: protectedHeader.protectedFirstByte,
                packetNumberBytes: protectedPNBytes)
        } catch {
            throw .protection(error)
        }

        // Step 4: Decode packet number.
        let actualPNLength = Int((unprotectedFirstByte & 0x03) + 1)
        let packetNumber = try decodeTruncatedPN(
            unprotectedPNBytes, length: actualPNLength, largestPN: largestPN)

        // Step 5: Validate header after HP removal.
        let longHeader: LongHeader
        do {
            longHeader = try protectedHeader.unprotect(
                unprotectedFirstByte: unprotectedFirstByte,
                packetNumber: packetNumber,
                packetNumberLength: actualPNLength)
        } catch {
            throw .headerValidation(error)
        }

        // Step 6: AAD + ciphertext boundary.
        var aad: [UInt8] = []
        aad.append(unprotectedFirstByte)
        append(bytes.extracting(1..<pnOffset), to: &aad)
        aad.append(contentsOf: unprotectedPNBytes.prefix(actualPNLength))

        let ciphertextStart = pnOffset + actualPNLength
        let ciphertextEnd: Int
        if let lengthValue = protectedHeader.length {
            let safeLengthValue: Int
            do {
                safeLengthValue = try SafeConversions.toInt(
                    lengthValue,
                    maxAllowed: ProtocolLimits.maxLongHeaderLength,
                    context: "Long header length field")
            } catch {
                throw .conversion(error)
            }
            let payloadLength: Int
            do {
                payloadLength = try SafeConversions.subtract(safeLengthValue, actualPNLength)
            } catch {
                throw .conversion(error)
            }
            ciphertextEnd = ciphertextStart + payloadLength
            guard ciphertextEnd <= bytes.count else {
                throw .invalidPacketFormat(
                    "Length field exceeds available data: \(lengthValue) bytes")
            }
        } else {
            ciphertextEnd = bytes.count
        }
        guard ciphertextStart <= ciphertextEnd else {
            throw .invalidPacketFormat("Negative ciphertext length")
        }
        let ciphertext = bytes.extracting(ciphertextStart..<ciphertextEnd)

        // Decrypt payload.
        let plaintext: [UInt8]
        do {
            plaintext = try protector.open(ciphertext, packetNumber: packetNumber, header: aad.span)
        } catch {
            throw .protection(error)
        }

        // Step 7: Decode frames.
        let frames: [Frame]
        do { frames = try frameCodec.decodeFrames(from: plaintext) } catch { throw .frame(error) }

        let actualPacketSize = pnOffset + actualPNLength + ciphertext.count
        return ParsedPacketCore(
            header: .long(longHeader),
            packetNumber: packetNumber,
            frames: frames,
            encryptionLevel: longHeader.packetType.encryptionLevel,
            packetSize: actualPacketSize)
    }

    /// Parses and decrypts a Short Header (1-RTT) packet, selecting the AEAD
    /// opener by Key Phase bit (RFC 9001 §6). Mirrors
    /// `PacketDecoder.decodeShortHeaderPacket` byte-for-byte.
    ///
    /// `headerProtectionProtector` removes header protection (its HP key is
    /// phase-independent, RFC 9001 §6.1) so the phase bit can be read; then
    /// `openerSelector(keyPhase, packetNumber)` chooses the AEAD opener. The selector — not this
    /// core — decides whether next-phase keys are derived, and a key update is
    /// committed by the adapter only after a successful open, so a forged packet
    /// that fails AEAD here never changes committed key state (RFC 9001 §6.3).
    public static func parseShortHeaderPacket(
        bytes: Span<UInt8>,
        dcidLength: Int,
        largestPN: UInt64,
        headerProtectionProtector: SuiteProtector?,
        openerSelector: (
            _ keyPhase: UInt8,
            _ packetNumber: UInt64
        ) throws(PacketParsingError) -> SuiteProtector?
    ) throws(PacketParsingError) -> ParsedPacketCore {
        // Step 1: Parse protected header.
        let protectedHeader: ProtectedShortHeader
        let headerLength: Int
        do {
            (protectedHeader, headerLength) = try ProtectedShortHeader.parse(
                from: bytes, dcidLength: dcidLength)
        } catch ProtectedShortHeader.ParseError.insufficientData {
            throw .insufficientData
        } catch {
            throw .invalidPacketFormat("Malformed short header")
        }

        guard bytes.count >= headerLength + 4 + 16 else {
            throw .insufficientData
        }

        let pnOffset = headerLength
        let sampleOffset = pnOffset + 4
        guard bytes.count >= sampleOffset + 16 else {
            throw .insufficientData
        }

        let protectedPNBytesEnd = min(pnOffset + 4, bytes.count)
        let protectedPNBytes = materialize(bytes.extracting(pnOffset..<protectedPNBytesEnd))
        let sample = bytes.extracting(sampleOffset..<(sampleOffset + 16))

        // Step 3: Remove header protection (HP key is phase-independent).
        guard let hpProtector = headerProtectionProtector else {
            throw .noProtector
        }
        let unprotectedFirstByte: UInt8
        let unprotectedPNBytes: [UInt8]
        do {
            (unprotectedFirstByte, unprotectedPNBytes) = try hpProtector.removeHeaderProtection(
                sample: sample, firstByte: protectedHeader.protectedFirstByte,
                packetNumberBytes: protectedPNBytes)
        } catch {
            throw .protection(error)
        }

        // Step 4: Read Key Phase bit (RFC 9001 §6.1: 0x04 of unprotected first byte).
        let keyPhase: UInt8 = (unprotectedFirstByte & 0x04) != 0 ? 1 : 0

        // Step 4b: Decode packet number.
        let actualPNLength = Int((unprotectedFirstByte & 0x03) + 1)
        let packetNumber = try decodeTruncatedPN(
            unprotectedPNBytes, length: actualPNLength, largestPN: largestPN)

        // Step 5: Validate header.
        let shortHeader: ShortHeader
        do {
            shortHeader = try protectedHeader.unprotect(
                unprotectedFirstByte: unprotectedFirstByte,
                packetNumber: packetNumber,
                packetNumberLength: actualPNLength)
        } catch {
            throw .headerValidation(error)
        }

        // Step 6: Select AEAD opener for this phase, then open.
        let opener: SuiteProtector?
        do { opener = try openerSelector(keyPhase, packetNumber) } catch { throw error }
        guard let opener = opener else {
            throw .noProtector
        }

        var aad: [UInt8] = []
        aad.append(unprotectedFirstByte)
        aad.append(contentsOf: protectedHeader.destinationConnectionID.bytes)
        aad.append(contentsOf: unprotectedPNBytes.prefix(actualPNLength))

        let ciphertextStart = pnOffset + actualPNLength
        let ciphertext = bytes.extracting(ciphertextStart..<bytes.count)

        let plaintext: [UInt8]
        do {
            plaintext = try opener.open(ciphertext, packetNumber: packetNumber, header: aad.span)
        } catch {
            throw .protection(error)
        }

        let frames: [Frame]
        do { frames = try frameCodec.decodeFrames(from: plaintext) } catch { throw .frame(error) }

        return ParsedPacketCore(
            header: .short(shortHeader),
            packetNumber: packetNumber,
            frames: frames,
            encryptionLevel: .application,
            packetSize: bytes.count,
            keyPhase: keyPhase)
    }

    // MARK: - Private helpers

    private static func protectHeader(
        packet: borrowing [UInt8],
        sampleOffset: Int,
        firstByte: UInt8,
        packetNumberBytes: [UInt8],
        protector: SuiteProtector
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let sample = packet.span.extracting(sampleOffset..<(sampleOffset + 16))
        return try protector.applyHeaderProtection(
            sample: sample,
            firstByte: firstByte,
            packetNumberBytes: packetNumberBytes
        )
    }

    private static func materialize(_ bytes: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        append(bytes, to: &result)
        return result
    }

    private static func append(_ bytes: Span<UInt8>, to output: inout [UInt8]) {
        var index = 0
        while index < bytes.count {
            output.append(bytes[index])
            index += 1
        }
    }

    /// Decodes the packet number from its (unprotected) bytes, big-endian
    /// truncated, then RFC 9000 §A.3 reconstruction.
    @inline(__always)
    private static func decodeTruncatedPN(
        _ pnBytes: [UInt8],
        length: Int,
        largestPN: UInt64
    ) throws(PacketParsingError) -> UInt64 {
        var truncatedPN: UInt64 = 0
        for i in 0..<length {
            truncatedPN = (truncatedPN << 8) | UInt64(pnBytes[i])
        }
        do {
            return try PacketNumberEncoding.decode(
                truncated: truncatedPN, length: length, largestPN: largestPN)
        } catch {
            throw .invalidPacketFormat("packet number decode: \(error)")
        }
    }

    /// Big-endian packet-number bytes of the given length.
    @inline(__always)
    private static func encodePacketNumberBytes(_ packetNumber: UInt64, length: Int) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        for i in (0..<length).reversed() {
            bytes.append(UInt8((packetNumber >> (i * 8)) & 0xFF))
        }
        return bytes
    }

    /// Replaces `count` bytes of `packet` starting at `offset` with `replacement`.
    @inline(__always)
    private static func replaceSubrange(
        _ packet: inout [UInt8],
        at offset: Int,
        count: Int,
        with replacement: [UInt8]
    ) {
        for i in 0..<count {
            packet[offset + i] = replacement[i]
        }
    }

    /// Builds the long header (first byte, version, DCIDs, optional Initial token).
    private static func buildLongHeader(_ header: LongHeader) throws(PacketParsingError) -> [UInt8] {
        var writer = QUICWireWriter()
        writer.writeByte(header.firstByte)
        header.version.encode(to: &writer)
        header.destinationConnectionID.encode(to: &writer)
        header.sourceConnectionID.encode(to: &writer)
        if header.packetType == .initial {
            let tokenLength = header.token?.count ?? 0
            do {
                try writer.writeVarint(UInt64(tokenLength))
            } catch {
                throw .invalidPacketFormat("Initial token length exceeds the QUIC varint range")
            }
            if let token = header.token {
                writer.writeBytes(token)
            }
        }
        return writer.finishArray()
    }

    /// Builds the long header followed by the Length field (Initial/Handshake/0-RTT).
    private static func buildLongHeaderWithLength(
        _ header: LongHeader,
        length: UInt64
    ) throws(PacketParsingError) -> [UInt8] {
        var bytes = try buildLongHeader(header)
        if header.hasPacketNumber {
            var writer = QUICWireWriter()
            do {
                try writer.writeVarint(length)
            } catch {
                throw .invalidPacketFormat("packet length exceeds the QUIC varint range")
            }
            bytes.append(contentsOf: writer.finishArray())
        }
        return bytes
    }

    /// Estimates the long header size (without Length field) for Initial padding.
    private static func estimateLongHeaderSize(_ header: LongHeader) -> Int {
        var size = 1  // First byte
        size += 4     // Version
        size += 1 + header.destinationConnectionID.length
        size += 1 + header.sourceConnectionID.length
        if header.packetType == .initial {
            let tokenLength = header.token?.count ?? 0
            size += Varint.encodedLength(for: UInt64(tokenLength))
            size += tokenLength
        }
        size += 2  // Length field estimate (2 bytes for typical packet sizes)
        return size
    }
}
