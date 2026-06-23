/// Host (non-Embedded) `CryptoProvider` conformance for the QUICCrypto adapter.
///
/// `QUICPacketProtectionCore` is generic over `C: CryptoProvider`; the host adapter
/// specialises it at `C = QUICFoundationProvider`, a swift-crypto / CryptoKit
/// (+ CommonCrypto for AES header protection) backend that is byte-identical to the
/// crypto behavior swift-quic shipped before the seam refactor.
///
/// This provider is QUICCrypto-internal (it lives in the adapter, never in the
/// Embedded core) because the shared `P2PCryptoFoundation.FoundationCryptoProvider`
/// pulls a vendored swift-crypto whose `.macOS(.v26)` platform floor is
/// incompatible with swift-quic's swift-certificates (`.macOS(.v12)`) graph. The
/// AEAD / HKDF / header-protection paths used by packet protection are implemented
/// faithfully. The key-agreement (X25519 / P-256 / P-384) and signature
/// (ECDSA-P256 / ECDSA-P384 / Ed25519) primitives are implemented faithfully over
/// swift-crypto too: `QUICTLSCore`'s `TLSKeyExchange` / `TLSSignatureSigner` /
/// `TLSSignatureVerifier` specialise at `C = QUICFoundationProvider` for the TLS 1.3
/// handshake (EC)DHE and CertificateVerify operations.

import Foundation
import QUICTLSCore
import Crypto
import P2PCoreCrypto

#if canImport(CommonCrypto)
import CommonCrypto
#endif

// MARK: - Provider

/// Aggregates swift-crypto–backed primitives behind `P2PCoreCrypto.CryptoProvider`.
public enum QUICFoundationProvider: CryptoProvider {
    public typealias AESGCM128  = QUICFoundationAEAD
    public typealias AESGCM256  = QUICFoundationAEAD
    public typealias ChaChaPoly = QUICFoundationAEAD

    public typealias SHA256 = QUICFoundationSHA256
    public typealias SHA384 = QUICFoundationSHA384

    public typealias HKDFSHA256 = QUICFoundationHKDFSHA256
    public typealias HKDFSHA384 = QUICFoundationHKDFSHA384

    public typealias HMACSHA1   = QUICFoundationHMACSHA1
    public typealias HMACSHA256 = QUICFoundationHMACSHA256
    public typealias HMACSHA384 = QUICFoundationHMACSHA384

    public typealias X25519        = QUICFoundationX25519
    public typealias P256Agreement = QUICFoundationP256Agreement
    public typealias P384Agreement = QUICFoundationP384Agreement

    public typealias Ed25519       = QUICFoundationEd25519
    public typealias P256Signature = QUICFoundationP256Signature
    public typealias P384Signature = QUICFoundationP384Signature

    public typealias Random           = QUICFoundationRandom
    public typealias Clock            = QUICFoundationClock
    public typealias HeaderProtection = QUICFoundationHeaderProtection

    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> QUICFoundationAEAD {
        try QUICFoundationAEAD(algorithm: .aes128gcm, key: key)
    }
    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> QUICFoundationAEAD {
        try QUICFoundationAEAD(algorithm: .aes256gcm, key: key)
    }
    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> QUICFoundationAEAD {
        try QUICFoundationAEAD(algorithm: .chacha20poly1305, key: key)
    }

    public static let random = QUICFoundationRandom()
    public static let clock  = QUICFoundationClock()
}

// MARK: - Span <-> bytes helpers (host-only)

extension Span where Element == UInt8 {
    @inline(__always)
    func providerArray() -> [UInt8] {
        var array = [UInt8]()
        array.reserveCapacity(count)
        for index in 0..<count { array.append(self[index]) }
        return array
    }

    @inline(__always)
    func providerData() -> Data { Data(providerArray()) }
}

// MARK: - AEAD

/// One keyed AEAD over swift-crypto. seal returns `ciphertext || tag`; open
/// rethrows `CryptoKitError.authenticationFailure` as `.authenticationFailure`
/// (no silent fallback).
public struct QUICFoundationAEAD: P2PCoreCrypto.AEAD {
    public static let nonceLength = 12
    public static let tagLength   = 16

    public enum Algorithm: Sendable {
        case aes128gcm, aes256gcm, chacha20poly1305
        var keyLength: Int {
            switch self {
            case .aes128gcm:        return 16
            case .aes256gcm:        return 32
            case .chacha20poly1305: return 32
            }
        }
    }

    private let algorithm: Algorithm
    private let key: SymmetricKey

    public init(algorithm: Algorithm, key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) {
        guard key.count == algorithm.keyLength else {
            throw .invalidLength(expected: algorithm.keyLength, actual: key.count)
        }
        self.algorithm = algorithm
        self.key = SymmetricKey(data: key.providerData())
    }

    public func seal(
        _ plaintext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard nonce.count == Self.nonceLength else {
            throw .invalidLength(expected: Self.nonceLength, actual: nonce.count)
        }
        let pt = plaintext.providerData()
        let nonceData = nonce.providerData()
        let aadData = aad.providerData()
        switch algorithm {
        case .aes128gcm, .aes256gcm:
            do {
                let n = try AES.GCM.Nonce(data: nonceData)
                let box = try AES.GCM.seal(pt, using: key, nonce: n, authenticating: aadData)
                return [UInt8](box.ciphertext) + [UInt8](box.tag)
            } catch { throw .providerFailure }
        case .chacha20poly1305:
            do {
                let n = try ChaChaPoly.Nonce(data: nonceData)
                let box = try ChaChaPoly.seal(pt, using: key, nonce: n, authenticating: aadData)
                return [UInt8](box.ciphertext) + [UInt8](box.tag)
            } catch { throw .providerFailure }
        }
    }

    public func open(
        _ ciphertext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard nonce.count == Self.nonceLength else {
            throw .invalidLength(expected: Self.nonceLength, actual: nonce.count)
        }
        guard ciphertext.count >= Self.tagLength else {
            throw .invalidLength(expected: Self.tagLength, actual: ciphertext.count)
        }
        let combined = ciphertext.providerArray()
        let splitIndex = combined.count - Self.tagLength
        let ctData = Data(combined[0..<splitIndex])
        let tagData = Data(combined[splitIndex..<combined.count])
        let nonceData = nonce.providerData()
        let aadData = aad.providerData()
        switch algorithm {
        case .aes128gcm, .aes256gcm:
            do {
                let n = try AES.GCM.Nonce(data: nonceData)
                let box = try AES.GCM.SealedBox(nonce: n, ciphertext: ctData, tag: tagData)
                return [UInt8](try AES.GCM.open(box, using: key, authenticating: aadData))
            } catch let error as CryptoKitError {
                throw Self.mapOpenError(error)
            } catch { throw .providerFailure }
        case .chacha20poly1305:
            do {
                let n = try ChaChaPoly.Nonce(data: nonceData)
                let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ctData, tag: tagData)
                return [UInt8](try ChaChaPoly.open(box, using: key, authenticating: aadData))
            } catch let error as CryptoKitError {
                throw Self.mapOpenError(error)
            } catch { throw .providerFailure }
        }
    }

    private static func mapOpenError(_ error: CryptoKitError) -> P2PCoreCrypto.CryptoError {
        switch error {
        case .authenticationFailure: return .authenticationFailure
        default:                     return .providerFailure
        }
    }
}

// MARK: - Hashes

public struct QUICFoundationSHA256: P2PCoreCrypto.HashFunction {
    public static let digestLength = 32
    public static let blockLength  = 64
    private var hasher = Crypto.SHA256()
    public init() {}
    public mutating func update(_ data: Span<UInt8>) { hasher.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](hasher.finalize()) }
}

public struct QUICFoundationSHA384: P2PCoreCrypto.HashFunction {
    public static let digestLength = 48
    public static let blockLength  = 128
    private var hasher = Crypto.SHA384()
    public init() {}
    public mutating func update(_ data: Span<UInt8>) { hasher.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](hasher.finalize()) }
}

// MARK: - HKDF

public struct QUICFoundationHKDFSHA256: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = QUICFoundationSHA256
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = Crypto.HKDF<Crypto.SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.providerData()), salt: salt.providerData())
        return prk.withUnsafeBytes { [UInt8]($0) }
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard length <= 255 * Hash.digestLength else {
            throw .invalidLength(expected: 255 * Hash.digestLength, actual: length)
        }
        let okm = Crypto.HKDF<Crypto.SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.providerData()),
            info: info.providerData(), outputByteCount: length)
        return okm.withUnsafeBytes { [UInt8]($0) }
    }
}

public struct QUICFoundationHKDFSHA384: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = QUICFoundationSHA384
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = Crypto.HKDF<Crypto.SHA384>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.providerData()), salt: salt.providerData())
        return prk.withUnsafeBytes { [UInt8]($0) }
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard length <= 255 * Hash.digestLength else {
            throw .invalidLength(expected: 255 * Hash.digestLength, actual: length)
        }
        let okm = Crypto.HKDF<Crypto.SHA384>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.providerData()),
            info: info.providerData(), outputByteCount: length)
        return okm.withUnsafeBytes { [UInt8]($0) }
    }
}

// MARK: - HMAC

public struct QUICFoundationHMACSHA256: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 32
    private var mac: Crypto.HMAC<Crypto.SHA256>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.SHA256>(key: SymmetricKey(data: key.providerData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.SHA256>.authenticationCode(
            for: message.providerData(), using: SymmetricKey(data: key.providerData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.SHA256>.isValidAuthenticationCode(
            mac.providerData(), authenticating: message.providerData(),
            using: SymmetricKey(data: key.providerData()))
    }
}

public struct QUICFoundationHMACSHA384: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 48
    private var mac: Crypto.HMAC<Crypto.SHA384>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.SHA384>(key: SymmetricKey(data: key.providerData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.SHA384>.authenticationCode(
            for: message.providerData(), using: SymmetricKey(data: key.providerData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.SHA384>.isValidAuthenticationCode(
            mac.providerData(), authenticating: message.providerData(),
            using: SymmetricKey(data: key.providerData()))
    }
}

public struct QUICFoundationHMACSHA1: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 20
    private var mac: Crypto.HMAC<Crypto.Insecure.SHA1>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.Insecure.SHA1>(key: SymmetricKey(data: key.providerData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.Insecure.SHA1>.authenticationCode(
            for: message.providerData(), using: SymmetricKey(data: key.providerData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.Insecure.SHA1>.isValidAuthenticationCode(
            mac.providerData(), authenticating: message.providerData(),
            using: SymmetricKey(data: key.providerData()))
    }
}

// MARK: - Header protection (RFC 9001 §5.4)

/// QUIC header protection over CommonCrypto (AES-ECB) + the in-repo RFC-8439
/// ChaCha20 block. Conforms `P2PCoreCrypto.HeaderProtectionProvider`.
public enum QUICFoundationHeaderProtection: P2PCoreCrypto.HeaderProtectionProvider {
    public static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard key.count == 16 || key.count == 32 else {
            throw .invalidLength(expected: 16, actual: key.count)
        }
        guard sample.count >= 16 else {
            throw .invalidLength(expected: 16, actual: sample.count)
        }
        let keyBytes = key.providerArray()
        let sampleBytes = Array(sample.providerArray()[0..<16])
        #if canImport(CommonCrypto)
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = keyBytes.withUnsafeBytes { kp in
            sampleBytes.withUnsafeBytes { ip in
                out.withUnsafeMutableBytes { op in
                    CCCrypt(
                        CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        kp.baseAddress, keyBytes.count, nil,
                        ip.baseAddress, 16, op.baseAddress, 16, &moved)
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else { throw .providerFailure }
        return Array(out[0..<5])
        #else
        // Off-Apple AES header protection (AES._CBC zero-IV) is not wired here.
        throw .unsupportedParameter
        #endif
    }

    public static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard key.count == 32 else {
            throw .invalidLength(expected: 32, actual: key.count)
        }
        guard sample.count >= 16 else {
            throw .invalidLength(expected: 16, actual: sample.count)
        }
        let sampleBytes = sample.providerArray()
        let counter = UInt32(sampleBytes[0])
            | (UInt32(sampleBytes[1]) << 8)
            | (UInt32(sampleBytes[2]) << 16)
            | (UInt32(sampleBytes[3]) << 24)
        let nonce = Data(sampleBytes[4..<16])
        do {
            // chaCha20Block (RFC 8439) is the in-repo pure-Swift block (ChaCha20Block.swift).
            let keystream = try chaCha20Block(key: Data(key.providerArray()), counter: counter, nonce: nonce)
            return Array(keystream.prefix(5))
        } catch {
            throw .providerFailure
        }
    }
}

// MARK: - Random / Clock

public struct QUICFoundationRandom: P2PCoreCrypto.RandomSource {
    public init() {}
    public func randomBytes(_ count: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        var out = [UInt8](repeating: 0, count: count)
        for i in 0..<count { out[i] = UInt8.random(in: .min ... .max, using: &rng) }
        return out
    }
    public func fill(_ buffer: inout [UInt8]) {
        var rng = SystemRandomNumberGenerator()
        for i in 0..<buffer.count { buffer[i] = UInt8.random(in: .min ... .max, using: &rng) }
    }
}

public struct QUICFoundationClock: P2PCoreCrypto.MonotonicClock {
    public init() {}
    public func monotonicMillis() -> UInt64 { monotonicNanos() / 1_000_000 }
    public func monotonicNanos() -> UInt64 {
        UInt64(DispatchTime.now().uptimeNanoseconds)
    }
}

// MARK: - Key agreement / signature

// X25519 / P-256 / P-384 ECDH and ECDSA-P256 / ECDSA-P384 / Ed25519 are
// implemented in their own files (QUICFoundationX25519 / QUICFoundationP256Agreement
// / QUICFoundationP384Agreement / QUICFoundationP256Signature /
// QUICFoundationP384Signature / QUICFoundationEd25519) and wired into the provider's
// typealiases above. They back QUICTLSCore's TLS 1.3 handshake (EC)DHE +
// CertificateVerify seam.
