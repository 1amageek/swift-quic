/// Packet Processor
///
/// High-level integration layer for QUIC packet encoding/decoding.
/// Combines PacketEncoder, PacketDecoder, and crypto contexts for
/// convenient packet processing.

import Foundation
import QUICCore
import QUICCrypto
import Synchronization

// MARK: - Packet Processor

/// High-level packet processor for QUIC connections
///
/// Provides a simplified API for packet encryption/decryption by combining:
/// - PacketEncoder/PacketDecoder for wire format handling
/// - CryptoContext for encryption/decryption at each level
/// - Coalesced packet handling
///
/// Thread-safe via Mutex for crypto context updates.
public final class PacketProcessor: Sendable {
    // MARK: - Properties

    /// Crypto contexts per encryption level
    private let contexts: Mutex<[EncryptionLevel: CryptoContext]>

    /// Packet encoder
    private let encoder = PacketEncoder()

    /// Packet decoder
    private let decoder = PacketDecoder()

    /// Local DCID length (for short header parsing)
    private let dcidLength: Mutex<Int>

    /// Largest packet numbers received per level (for PN decoding)
    private let largestReceivedPN: Mutex<[EncryptionLevel: UInt64]>

    // MARK: - Initialization

    /// Creates a new packet processor
    /// - Parameter dcidLength: Expected DCID length for short headers
    public init(dcidLength: Int = 8) {
        self.contexts = Mutex([:])
        self.dcidLength = Mutex(dcidLength)
        self.largestReceivedPN = Mutex([:])
    }

    // MARK: - Crypto Context Management

    /// Installs a crypto context for an encryption level
    /// - Parameters:
    ///   - context: The crypto context
    ///   - level: The encryption level
    public func installContext(_ context: CryptoContext, for level: EncryptionLevel) {
        contexts.withLock { $0[level] = context }
    }

    /// Discards crypto context for an encryption level
    /// - Parameter level: The level to discard
    public func discardContext(for level: EncryptionLevel) {
        _ = contexts.withLock { $0.removeValue(forKey: level) }
    }

    /// Gets the crypto context for a level
    /// - Parameter level: The encryption level
    /// - Returns: The context, or nil if not installed
    public func context(for level: EncryptionLevel) -> CryptoContext? {
        contexts.withLock { $0[level] }
    }

    /// Updates the DCID length (for short header parsing)
    /// - Parameter length: The new DCID length
    public func setDCIDLength(_ length: Int) {
        dcidLength.withLock { $0 = length }
    }

    // MARK: - Unified Key Management

    /// Installs keys from TLS keying material
    ///
    /// This is the unified entry point for key installation.
    /// PacketProcessor is the single source of truth for crypto contexts.
    ///
    /// - Parameters:
    ///   - info: Keys available info from TLS provider
    ///   - isClient: Whether this is the client side
    /// - Throws: Error if key derivation or context creation fails
    public func installKeys(_ info: KeysAvailableInfo, isClient: Bool) throws {
        // Derive key material from traffic secrets
        let clientKeys = try KeyMaterial.derive(from: info.clientSecret)
        let serverKeys = try KeyMaterial.derive(from: info.serverSecret)

        // Client reads server keys, writes client keys (and vice versa)
        let readKeys = isClient ? serverKeys : clientKeys
        let writeKeys = isClient ? clientKeys : serverKeys

        // Create opener (for decryption) and sealer (for encryption)
        let opener = try AES128GCMOpener(keyMaterial: readKeys)
        let sealer = try AES128GCMSealer(keyMaterial: writeKeys)

        // Install the crypto context
        let context = CryptoContext(opener: opener, sealer: sealer)
        installContext(context, for: info.level)
    }

    /// Discards keys for an encryption level
    ///
    /// This is the unified entry point for key discarding.
    /// Call this after all packets at this level have been sent.
    ///
    /// - Parameter level: The encryption level to discard
    public func discardKeys(for level: EncryptionLevel) {
        discardContext(for: level)
    }

    /// Checks if keys are installed for a level
    /// - Parameter level: The encryption level
    /// - Returns: True if keys are available for this level
    public func hasKeys(for level: EncryptionLevel) -> Bool {
        contexts.withLock { $0[level] != nil }
    }

    // MARK: - Packet Decryption

    /// Decrypts a single QUIC packet
    /// - Parameter data: The encrypted packet data
    /// - Returns: The parsed packet with decrypted frames
    /// - Throws: PacketCodecError if decryption fails
    public func decryptPacket(_ data: Data) throws -> ParsedPacket {
        // Peek at first byte to determine encryption level
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let firstByte = data[data.startIndex]
        let isLongHeader = PacketHeader.isLongHeader(firstByte: firstByte)

        let level: EncryptionLevel
        if isLongHeader {
            // Parse header to get packet type
            let (header, _) = try PacketHeader.parse(from: data)
            level = header.packetType.encryptionLevel
        } else {
            level = .application
        }

        // Get opener for this level
        guard let ctx = contexts.withLock({ $0[level] }),
              let opener = ctx.opener else {
            throw PacketCodecError.noOpener
        }

        // Get largest PN for this level
        let largestPN = largestReceivedPN.withLock { $0[level] ?? 0 }

        // Get DCID length
        let dcid = dcidLength.withLock { $0 }

        // Decode packet
        let parsed = try decoder.decodePacket(
            data: data,
            dcidLength: dcid,
            opener: opener,
            largestPN: largestPN
        )

        // Update largest PN if this is larger
        if parsed.packetNumber > largestPN {
            largestReceivedPN.withLock { $0[level] = parsed.packetNumber }
        }

        return parsed
    }

    /// Decrypts all packets from a coalesced UDP datagram
    /// - Parameter datagram: The UDP datagram
    /// - Returns: Array of parsed packets
    /// - Throws: Error if any packet fails to decrypt
    public func decryptDatagram(_ datagram: Data) throws -> [ParsedPacket] {
        // Split coalesced packets
        let dcid = dcidLength.withLock { $0 }
        let packetInfos = try CoalescedPacketParser.parse(datagram: datagram, dcidLength: dcid)

        var results: [ParsedPacket] = []
        for info in packetInfos {
            let parsed = try decryptPacket(info.data)
            results.append(parsed)
        }
        return results
    }

    // MARK: - Packet Encryption

    /// Encrypts a Long Header packet
    /// - Parameters:
    ///   - frames: Frames to include
    ///   - header: The long header template
    ///   - packetNumber: The packet number
    ///   - padToMinimum: If true and this is an Initial packet, pad to 1200 bytes
    /// - Returns: The encrypted packet data
    /// - Throws: PacketCodecError if encryption fails
    public func encryptLongHeaderPacket(
        frames: [Frame],
        header: LongHeader,
        packetNumber: UInt64,
        padToMinimum: Bool = true
    ) throws -> Data {
        let level = header.packetType.encryptionLevel

        guard let ctx = contexts.withLock({ $0[level] }),
              let sealer = ctx.sealer else {
            throw PacketCodecError.noSealer
        }

        return try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer,
            padToMinimum: padToMinimum
        )
    }

    /// Encrypts a Short Header packet
    /// - Parameters:
    ///   - frames: Frames to include
    ///   - header: The short header template
    ///   - packetNumber: The packet number
    /// - Returns: The encrypted packet data
    /// - Throws: PacketCodecError if encryption fails
    public func encryptShortHeaderPacket(
        frames: [Frame],
        header: ShortHeader,
        packetNumber: UInt64
    ) throws -> Data {
        guard let ctx = contexts.withLock({ $0[.application] }),
              let sealer = ctx.sealer else {
            throw PacketCodecError.noSealer
        }

        return try encoder.encodeShortHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer
        )
    }

    // MARK: - Coalesced Packet Building

    /// Builds a coalesced packet from multiple packets
    /// - Parameters:
    ///   - packets: Array of (frames, header, packetNumber) tuples
    ///   - maxSize: Maximum datagram size (default: 1200)
    /// - Returns: The coalesced datagram
    /// - Throws: Error if encryption fails
    public func buildCoalescedPacket(
        packets: [(frames: [Frame], header: PacketHeader, packetNumber: UInt64)],
        maxSize: Int = 1200
    ) throws -> Data {
        var builder = CoalescedPacketBuilder(maxDatagramSize: maxSize)

        // Sort by packet type order (Initial -> Handshake -> 0-RTT -> 1-RTT)
        let sorted = packets.sorted { lhs, rhs in
            CoalescedPacketOrder.sortOrder(for: lhs.header.packetType) <
            CoalescedPacketOrder.sortOrder(for: rhs.header.packetType)
        }

        for (frames, header, pn) in sorted {
            let encoded: Data
            switch header {
            case .long(let longHeader):
                encoded = try encryptLongHeaderPacket(
                    frames: frames,
                    header: longHeader,
                    packetNumber: pn
                )
            case .short(let shortHeader):
                encoded = try encryptShortHeaderPacket(
                    frames: frames,
                    header: shortHeader,
                    packetNumber: pn
                )
            }

            if !builder.addPacket(encoded) {
                break  // No more room
            }
        }

        return builder.build()
    }

    // MARK: - Header Extraction (No Decryption)

    /// Extracts the destination connection ID from a packet without decryption
    ///
    /// Useful for routing packets to the correct connection.
    ///
    /// - Parameter data: The packet data
    /// - Returns: The destination connection ID
    /// - Throws: Error if the header cannot be parsed
    public func extractDestinationConnectionID(from data: Data) throws -> ConnectionID {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let firstByte = data[data.startIndex]

        if PacketHeader.isLongHeader(firstByte: firstByte) {
            // Long header: parse to get DCID
            let (header, _) = try PacketHeader.parse(from: data)
            return header.destinationConnectionID
        } else {
            // Short header: DCID follows first byte
            let dcid = dcidLength.withLock { $0 }
            guard data.count >= 1 + dcid else {
                throw PacketCodecError.insufficientData
            }
            let dcidBytes = data[(data.startIndex + 1)..<(data.startIndex + 1 + dcid)]
            return ConnectionID(bytes: Data(dcidBytes))
        }
    }

    /// Extracts packet type from a packet without decryption
    /// - Parameter data: The packet data
    /// - Returns: The packet type
    /// - Throws: Error if the header cannot be parsed
    public func extractPacketType(from data: Data) throws -> PacketType {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let firstByte = data[data.startIndex]

        if PacketHeader.isLongHeader(firstByte: firstByte) {
            // Check for version negotiation first
            guard data.count >= 5 else {
                throw PacketCodecError.insufficientData
            }
            let version = UInt32(data[data.startIndex + 1]) << 24 |
                         UInt32(data[data.startIndex + 2]) << 16 |
                         UInt32(data[data.startIndex + 3]) << 8 |
                         UInt32(data[data.startIndex + 4])

            if version == 0 {
                return .versionNegotiation
            }

            // Extract type from first byte
            let typeValue = (firstByte >> 4) & 0x03
            switch typeValue {
            case 0x00: return .initial
            case 0x01: return .zeroRTT
            case 0x02: return .handshake
            case 0x03: return .retry
            default: return .initial
            }
        } else {
            return .oneRTT
        }
    }
}

// MARK: - Utility Extensions

extension PacketProcessor {
    /// Creates initial crypto contexts from a connection ID
    /// - Parameters:
    ///   - connectionID: The destination connection ID from the first Initial packet
    ///   - isClient: Whether this is the client side
    ///   - version: The QUIC version
    /// - Returns: The client and server key material
    public func deriveAndInstallInitialKeys(
        connectionID: ConnectionID,
        isClient: Bool,
        version: QUICVersion
    ) throws -> (client: KeyMaterial, server: KeyMaterial) {
        // Derive initial secrets
        let initialSecrets = try InitialSecrets.derive(connectionID: connectionID, version: version)

        // Derive key material from secrets
        let clientKeys = try KeyMaterial.derive(from: initialSecrets.clientSecret)
        let serverKeys = try KeyMaterial.derive(from: initialSecrets.serverSecret)

        // Create opener/sealer
        let readKeys = isClient ? serverKeys : clientKeys
        let writeKeys = isClient ? clientKeys : serverKeys

        let opener = try AES128GCMOpener(keyMaterial: readKeys)
        let sealer = try AES128GCMSealer(keyMaterial: writeKeys)

        // Install context
        let context = CryptoContext(opener: opener, sealer: sealer)
        installContext(context, for: .initial)

        return (client: clientKeys, server: serverKeys)
    }
}
