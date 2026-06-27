/// The closed cipher-suite enum that replaces the `any PacketOpener` /
/// `any PacketSealer` existentials with a generic, Embedded-clean value type.
///
/// QUIC mandates exactly two AEAD suites for packet protection
/// (RFC 9001 §5.3): `AEAD_AES_128_GCM` and `AEAD_CHACHA20_POLY1305`; key updates
/// and TLS may additionally negotiate `AEAD_AES_256_GCM`. Rather than erase the
/// concrete protector behind `any`, `SuiteProtector<C>` is a closed `enum` over
/// the generic ``PacketProtector`` specialised at each of the provider's three
/// AEAD associated types. A generic upper layer (`<C: CryptoProvider>`)
/// specialises cleanly under Embedded Swift; the adapter instantiates it at
/// `C = FoundationEssentialsCryptoProvider`.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreCrypto

/// The packet-protection cipher suite (RFC 9001 §5.3 / TLS 1.3 §B.4).
public enum QUICProtectionSuite: Sendable, Equatable {
    /// `TLS_AES_128_GCM_SHA256` — 16-byte key, 16-byte HP key.
    case aes128GCM
    /// `TLS_AES_256_GCM_SHA384` — 32-byte key, 32-byte HP key.
    case aes256GCM
    /// `TLS_CHACHA20_POLY1305_SHA256` — 32-byte key, 32-byte HP key.
    case chaCha20Poly1305

    /// The AEAD/HP key length in bytes.
    public var keyLength: Int {
        switch self {
        case .aes128GCM:        return 16
        case .aes256GCM:        return 32
        case .chaCha20Poly1305: return 32
        }
    }

    /// Whether header protection uses the AES-ECB block mask (`true`) or the
    /// ChaCha20 block mask (`false`).
    public var usesAESHeaderProtection: Bool {
        switch self {
        case .aes128GCM, .aes256GCM: return true
        case .chaCha20Poly1305:      return false
        }
    }
}

/// A cipher-suite-tagged packet protector. Carries the generic
/// ``PacketProtector`` for the selected AEAD; provides the uniform
/// seal/open/header-protection surface that the codec needs without `any`.
public enum SuiteProtector<C: CryptoProvider>: Sendable {
    case aes128GCM(PacketProtector<C, C.AESGCM128>)
    case aes256GCM(PacketProtector<C, C.AESGCM256>)
    case chaCha20Poly1305(PacketProtector<C, C.ChaChaPoly>)

    /// The suite this protector was built for.
    public var suite: QUICProtectionSuite {
        switch self {
        case .aes128GCM:        return .aes128GCM
        case .aes256GCM:        return .aes256GCM
        case .chaCha20Poly1305: return .chaCha20Poly1305
        }
    }

    // MARK: - Construction (RFC 9001 §5.1 key material)

    /// Builds a protector from the derived key material for `suite`.
    ///
    /// - `key`: the AEAD key ("quic key"); 16 or 32 bytes per suite.
    /// - `iv`: the 12-byte packet-protection IV ("quic iv").
    /// - `hpKey`: the header-protection key ("quic hp").
    ///
    /// Routes AEAD construction through the `CryptoProvider` seam factories
    /// (`C.makeAESGCM128` / `C.makeAESGCM256` / `C.makeChaChaPoly`).
    public static func make(
        suite: QUICProtectionSuite,
        key: [UInt8],
        iv: [UInt8],
        hpKey: [UInt8]
    ) throws(PacketProtectionError) -> SuiteProtector<C> {
        switch suite {
        case .aes128GCM:
            let aead: C.AESGCM128
            do { aead = try C.makeAESGCM128(key: key.span) } catch { throw .crypto(error) }
            let protector = try PacketProtector<C, C.AESGCM128>(
                aead: aead, iv: iv, hpKey: hpKey, usesAESHeaderProtection: true)
            return .aes128GCM(protector)
        case .aes256GCM:
            let aead: C.AESGCM256
            do { aead = try C.makeAESGCM256(key: key.span) } catch { throw .crypto(error) }
            let protector = try PacketProtector<C, C.AESGCM256>(
                aead: aead, iv: iv, hpKey: hpKey, usesAESHeaderProtection: true)
            return .aes256GCM(protector)
        case .chaCha20Poly1305:
            let aead: C.ChaChaPoly
            do { aead = try C.makeChaChaPoly(key: key.span) } catch { throw .crypto(error) }
            let protector = try PacketProtector<C, C.ChaChaPoly>(
                aead: aead, iv: iv, hpKey: hpKey, usesAESHeaderProtection: false)
            return .chaCha20Poly1305(protector)
        }
    }

    // MARK: - Uniform protection surface (dispatch without `any`)

    /// Seals `plaintext`, returning `ciphertext || tag` (RFC 9001 §5.3).
    public func seal(
        _ plaintext: [UInt8],
        packetNumber: UInt64,
        header: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        switch self {
        case .aes128GCM(let p):        return try p.seal(plaintext, packetNumber: packetNumber, header: header)
        case .aes256GCM(let p):        return try p.seal(plaintext, packetNumber: packetNumber, header: header)
        case .chaCha20Poly1305(let p): return try p.seal(plaintext, packetNumber: packetNumber, header: header)
        }
    }

    /// Opens `ciphertext || tag`, returning the plaintext (RFC 9001 §5.3).
    /// Throws on a tag mismatch — no silent fallback.
    public func open(
        _ ciphertext: [UInt8],
        packetNumber: UInt64,
        header: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        switch self {
        case .aes128GCM(let p):        return try p.open(ciphertext, packetNumber: packetNumber, header: header)
        case .aes256GCM(let p):        return try p.open(ciphertext, packetNumber: packetNumber, header: header)
        case .chaCha20Poly1305(let p): return try p.open(ciphertext, packetNumber: packetNumber, header: header)
        }
    }

    /// Computes the 5-byte header-protection mask for `sample` (RFC 9001 §5.4).
    public func headerProtectionMask(sample: [UInt8]) throws(PacketProtectionError) -> [UInt8] {
        switch self {
        case .aes128GCM(let p):        return try p.headerProtectionMask(sample: sample)
        case .aes256GCM(let p):        return try p.headerProtectionMask(sample: sample)
        case .chaCha20Poly1305(let p): return try p.headerProtectionMask(sample: sample)
        }
    }

    /// Applies header protection (RFC 9001 §5.4.1).
    public func applyHeaderProtection(
        sample: [UInt8],
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        switch self {
        case .aes128GCM(let p):        return try p.applyHeaderProtection(sample: sample, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
        case .aes256GCM(let p):        return try p.applyHeaderProtection(sample: sample, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
        case .chaCha20Poly1305(let p): return try p.applyHeaderProtection(sample: sample, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
        }
    }

    /// Removes header protection (RFC 9001 §5.4.1).
    public func removeHeaderProtection(
        sample: [UInt8],
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        switch self {
        case .aes128GCM(let p):        return try p.removeHeaderProtection(sample: sample, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
        case .aes256GCM(let p):        return try p.removeHeaderProtection(sample: sample, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
        case .chaCha20Poly1305(let p): return try p.removeHeaderProtection(sample: sample, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
        }
    }
}
