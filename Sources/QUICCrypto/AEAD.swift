/// QUIC AEAD (Authenticated Encryption with Associated Data) — host adapter.
///
/// QUIC uses AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 for packet protection
/// (RFC 9001 §5.3) plus AES/ChaCha20 header protection (§5.4).
///
/// This file is the **host (non-Embedded) adapter** over the Embedded-clean
/// `QUICPacketProtectionCore`: the concrete opener/sealer/header-protection types
/// keep their `Data`-based public API (so existing call sites and tests compile
/// unchanged), but all AEAD and header-protection crypto now routes through the
/// `CryptoProvider` / `HeaderProtectionProvider` seam, specialised at
/// `C = FoundationCryptoProvider`. The generic `PacketProtector<C, A>` /
/// `SuiteProtector<C>` value types live in `QUICPacketProtectionCore`; the
/// connection/codec layers now hold the concrete ``QUICPacketProtector`` (a
/// `SuiteProtector<QUICFoundationProvider>` wrapper) directly, so no
/// `any PacketOpener` / `any PacketSealer` existential remains on the crypto path.
/// These concrete `AES128GCMOpener`/`Sealer` and `ChaCha20…Opener`/`Sealer` types
/// remain for the existing unit tests and direct callers.

import Foundation
import QUICTLSCore
import Crypto
import QUICCore
import QUICPacketProtectionCore
import P2PCoreCrypto
import P2PCoreBytes

// MARK: - Suite mapping

extension QUICCipherSuite {
    /// Maps the adapter's cipher-suite enum to the core's ``QUICProtectionSuite``.
    var protectionSuite: QUICProtectionSuite {
        switch self {
        case .aes128GcmSha256:        return .aes128GCM
        case .chacha20Poly1305Sha256: return .chaCha20Poly1305
        }
    }
}

/// Builds a `SuiteProtector<QUICFoundationProvider>` from `KeyMaterial`, routing
/// AEAD construction + header-protection through the seam. Surfaces a typed
/// ``CryptoError`` instead of the core's ``PacketProtectionError`` so the adapter
/// API is unchanged — no silent fallback.
func makeSuiteProtector(from keyMaterial: KeyMaterial) throws -> SuiteProtector<QUICFoundationProvider> {
    let suite = keyMaterial.cipherSuite.protectionSuite
    guard keyMaterial.iv.count == 12 else {
        throw CryptoError.invalidIVLength(expected: 12, actual: keyMaterial.iv.count)
    }
    let key = [UInt8](keyMaterial.key.withUnsafeBytes { Data($0) })
    let iv = [UInt8](keyMaterial.iv)
    let hpKey = [UInt8](keyMaterial.hp.withUnsafeBytes { Data($0) })
    do {
        return try SuiteProtector<QUICFoundationProvider>.make(
            suite: suite, key: key, iv: iv, hpKey: hpKey)
    } catch {
        throw error.asCryptoError
    }
}

extension PacketProtectionError {
    /// Maps the core's typed protection error onto the adapter's ``CryptoError``,
    /// preserving the failure cause (no silent fallback).
    var asCryptoError: CryptoError {
        switch self {
        case .invalidIVLength(let expected, let actual):
            return .invalidIVLength(expected: expected, actual: actual)
        case .insufficientSample(let expected, let actual):
            return .insufficientSample(expected: expected, actual: actual)
        case .ciphertextTooShort:
            return .aeadFailed
        case .crypto(let cryptoError):
            switch cryptoError {
            case .invalidLength(let expected, let actual):
                return .invalidIVLength(expected: expected, actual: actual)
            case .authenticationFailure:
                // AEAD authentication tag verification failed: this is an
                // AEAD-open failure, not a header-protection failure.
                return .aeadFailed
            case .providerFailure, .unsupportedParameter,
                 .keyAgreementFailure, .invalidSignature:
                return .headerProtectionFailed
            }
        }
    }
}

// MARK: - AES-128 Header Protection

/// AES based header protection (RFC 9001 Section 5.4.3).
///
/// Computes the 5-byte mask via the `HeaderProtectionProvider` seam
/// (`QUICFoundationHeaderProtection.aesECBBlockMask`).
public struct AES128HeaderProtection: HeaderProtection, Sendable {
    private let key: [UInt8]

    /// Creates AES header protection with the given key.
    /// - Parameter key: The header protection key (16 bytes for AES-128).
    public init(key: SymmetricKey) {
        self.key = [UInt8](key.withUnsafeBytes { Data($0) })
    }

    public func mask(sample: Data) throws -> Data {
        guard sample.count >= 16 else {
            throw CryptoError.insufficientSample(expected: 16, actual: sample.count)
        }
        let sampleBytes = [UInt8](sample.prefix(16))
        do {
            let mask = try QUICFoundationHeaderProtection.aesECBBlockMask(
                key: key.span, sample: sampleBytes.span)
            return Data(mask)
        } catch {
            throw CryptoError.headerProtectionFailed
        }
    }
}

// MARK: - AES-128-GCM Opener

/// AES-128-GCM packet opener (decryption). Thin adapter over
/// `SuiteProtector<QUICFoundationProvider>` (AES-128-GCM case).
public struct AES128GCMOpener: PacketOpener, Sendable {
    private let protector: SuiteProtector<QUICFoundationProvider>

    /// AES-128-GCM requires 12-byte IV
    public static let ivLength = 12

    /// Creates an AES-128-GCM opener.
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(key: SymmetricKey, iv: Data, hp: SymmetricKey) throws {
        guard iv.count == Self.ivLength else {
            throw CryptoError.invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        let keyBytes = [UInt8](key.withUnsafeBytes { Data($0) })
        let hpBytes = [UInt8](hp.withUnsafeBytes { Data($0) })
        do {
            self.protector = try SuiteProtector<QUICFoundationProvider>.make(
                suite: .aes128GCM, key: keyBytes, iv: [UInt8](iv), hpKey: hpBytes)
        } catch {
            throw error.asCryptoError
        }
    }

    /// Creates an opener from key material.
    public init(keyMaterial: KeyMaterial) throws {
        self.protector = try makeSuiteProtector(from: keyMaterial)
    }

    public func open(ciphertext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        do {
            let plaintext = try protector.open(
                [UInt8](ciphertext), packetNumber: packetNumber, header: [UInt8](header))
            return Data(plaintext)
        } catch {
            // RFC 9001: AEAD open failure (incl. tag mismatch) MUST be reported,
            // never a silent garbage/empty return.
            throw QUICError.decryptionFailed
        }
    }

    public func removeHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        do {
            let (fb, pn) = try protector.removeHeaderProtection(
                sample: [UInt8](sample), firstByte: firstByte,
                packetNumberBytes: [UInt8](packetNumberBytes))
            return (fb, Data(pn))
        } catch {
            throw error.asCryptoError
        }
    }
}

// MARK: - AES-128-GCM Sealer

/// AES-128-GCM packet sealer (encryption). Thin adapter over
/// `SuiteProtector<QUICFoundationProvider>` (AES-128-GCM case).
public struct AES128GCMSealer: PacketSealer, Sendable {
    private let protector: SuiteProtector<QUICFoundationProvider>

    /// AES-128-GCM requires 12-byte IV
    public static let ivLength = 12

    /// Creates an AES-128-GCM sealer.
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(key: SymmetricKey, iv: Data, hp: SymmetricKey) throws {
        guard iv.count == Self.ivLength else {
            throw CryptoError.invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        let keyBytes = [UInt8](key.withUnsafeBytes { Data($0) })
        let hpBytes = [UInt8](hp.withUnsafeBytes { Data($0) })
        do {
            self.protector = try SuiteProtector<QUICFoundationProvider>.make(
                suite: .aes128GCM, key: keyBytes, iv: [UInt8](iv), hpKey: hpBytes)
        } catch {
            throw error.asCryptoError
        }
    }

    /// Creates a sealer from key material.
    public init(keyMaterial: KeyMaterial) throws {
        self.protector = try makeSuiteProtector(from: keyMaterial)
    }

    public func seal(plaintext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        do {
            let ciphertext = try protector.seal(
                [UInt8](plaintext), packetNumber: packetNumber, header: [UInt8](header))
            return Data(ciphertext)
        } catch {
            throw error.asCryptoError
        }
    }

    public func applyHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        do {
            let (fb, pn) = try protector.applyHeaderProtection(
                sample: [UInt8](sample), firstByte: firstByte,
                packetNumberBytes: [UInt8](packetNumberBytes))
            return (fb, Data(pn))
        } catch {
            throw error.asCryptoError
        }
    }
}

// MARK: - ChaCha20 Header Protection

/// ChaCha20-based header protection (RFC 9001 Section 5.4.4).
///
/// Computes the 5-byte mask via the `HeaderProtectionProvider` seam
/// (`QUICFoundationHeaderProtection.chaCha20BlockMask`).
public struct ChaCha20HeaderProtection: HeaderProtection, Sendable {
    private let key: [UInt8]

    /// Creates ChaCha20 header protection with the given key.
    /// - Parameter key: The header protection key (32 bytes).
    public init(key: SymmetricKey) {
        precondition(key.bitCount == 256, "ChaCha20 header protection requires 32-byte key")
        self.key = [UInt8](key.withUnsafeBytes { Data($0) })
    }

    public func mask(sample: Data) throws -> Data {
        guard sample.count >= 16 else {
            throw CryptoError.insufficientSample(expected: 16, actual: sample.count)
        }
        let sampleBytes = [UInt8](sample.prefix(16))
        do {
            let mask = try QUICFoundationHeaderProtection.chaCha20BlockMask(
                key: key.span, sample: sampleBytes.span)
            return Data(mask)
        } catch {
            throw CryptoError.headerProtectionFailed
        }
    }
}

// MARK: - ChaCha20-Poly1305 Opener

/// ChaCha20-Poly1305 packet opener (decryption). Thin adapter over
/// `SuiteProtector<QUICFoundationProvider>` (ChaCha20-Poly1305 case).
public struct ChaCha20Poly1305Opener: PacketOpener, Sendable {
    private let protector: SuiteProtector<QUICFoundationProvider>

    /// ChaCha20-Poly1305 requires 12-byte IV
    public static let ivLength = 12

    /// Key size for ChaCha20-Poly1305 (32 bytes)
    public static let keySize = 32

    /// Creates a ChaCha20-Poly1305 opener.
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(key: SymmetricKey, iv: Data, hp: SymmetricKey) throws {
        guard iv.count == Self.ivLength else {
            throw CryptoError.invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        let keyBytes = [UInt8](key.withUnsafeBytes { Data($0) })
        let hpBytes = [UInt8](hp.withUnsafeBytes { Data($0) })
        do {
            self.protector = try SuiteProtector<QUICFoundationProvider>.make(
                suite: .chaCha20Poly1305, key: keyBytes, iv: [UInt8](iv), hpKey: hpBytes)
        } catch {
            throw error.asCryptoError
        }
    }

    /// Creates an opener from key material.
    public init(keyMaterial: KeyMaterial) throws {
        self.protector = try makeSuiteProtector(from: keyMaterial)
    }

    public func open(ciphertext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        do {
            let plaintext = try protector.open(
                [UInt8](ciphertext), packetNumber: packetNumber, header: [UInt8](header))
            return Data(plaintext)
        } catch {
            throw QUICError.decryptionFailed
        }
    }

    public func removeHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        do {
            let (fb, pn) = try protector.removeHeaderProtection(
                sample: [UInt8](sample), firstByte: firstByte,
                packetNumberBytes: [UInt8](packetNumberBytes))
            return (fb, Data(pn))
        } catch {
            throw error.asCryptoError
        }
    }
}

// MARK: - ChaCha20-Poly1305 Sealer

/// ChaCha20-Poly1305 packet sealer (encryption). Thin adapter over
/// `SuiteProtector<QUICFoundationProvider>` (ChaCha20-Poly1305 case).
public struct ChaCha20Poly1305Sealer: PacketSealer, Sendable {
    private let protector: SuiteProtector<QUICFoundationProvider>

    /// ChaCha20-Poly1305 requires 12-byte IV
    public static let ivLength = 12

    /// Key size for ChaCha20-Poly1305 (32 bytes)
    public static let keySize = 32

    /// Creates a ChaCha20-Poly1305 sealer.
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(key: SymmetricKey, iv: Data, hp: SymmetricKey) throws {
        guard iv.count == Self.ivLength else {
            throw CryptoError.invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        let keyBytes = [UInt8](key.withUnsafeBytes { Data($0) })
        let hpBytes = [UInt8](hp.withUnsafeBytes { Data($0) })
        do {
            self.protector = try SuiteProtector<QUICFoundationProvider>.make(
                suite: .chaCha20Poly1305, key: keyBytes, iv: [UInt8](iv), hpKey: hpBytes)
        } catch {
            throw error.asCryptoError
        }
    }

    /// Creates a sealer from key material.
    public init(keyMaterial: KeyMaterial) throws {
        self.protector = try makeSuiteProtector(from: keyMaterial)
    }

    public func seal(plaintext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        do {
            let ciphertext = try protector.seal(
                [UInt8](plaintext), packetNumber: packetNumber, header: [UInt8](header))
            return Data(ciphertext)
        } catch {
            throw error.asCryptoError
        }
    }

    public func applyHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        do {
            let (fb, pn) = try protector.applyHeaderProtection(
                sample: [UInt8](sample), firstByte: firstByte,
                packetNumberBytes: [UInt8](packetNumberBytes))
            return (fb, Data(pn))
        } catch {
            throw error.asCryptoError
        }
    }
}
