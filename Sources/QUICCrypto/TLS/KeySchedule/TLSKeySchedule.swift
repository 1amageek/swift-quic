/// TLS 1.3 Key Schedule (RFC 8446 Section 7.1) — QUICCrypto host adapter.
///
/// The pure RFC 8446 §7.1 derivation logic lives in `QUICTLSCore`
/// (`TLSKeyScheduleCore<C>`), Embedded-clean and generic over the `CryptoProvider`
/// seam. This adapter specialises the core at `C = QUICCryptoProvider`
/// (swift-crypto / CryptoKit) and bridges the public `Data` / `SymmetricKey` /
/// `SharedSecret` surface so existing call sites and tests are unchanged. The
/// derivation is byte-identical to the pre-seam swift-crypto implementation.
///
/// ```
///             0
///             |
///   PSK ->  HKDF-Extract = Early Secret
///             |
///             v   Derive-Secret(., "derived", "")
///  (EC)DHE -> HKDF-Extract = Handshake Secret
///             |
///             +--> Derive-Secret(., "c hs traffic" / "s hs traffic", CH...SH)
///             |
///             v   Derive-Secret(., "derived", "")
///     0 -> HKDF-Extract = Master Secret
///             |
///             +--> Derive-Secret(., "c ap traffic" / "s ap traffic", CH...SF)
///             +--> Derive-Secret(., "exp master", CH...SF)
///             +--> Derive-Secret(., "res master", CH...CF)
/// ```

import Foundation
import Crypto
import QUICTLSCore
import P2PCrypto

// MARK: - CipherSuite <-> Core bridge

extension CipherSuite {
    /// The Embedded-clean `QUICTLSCore` description of this cipher suite (hash + key/iv
    /// lengths) that drives the key schedule.
    var coreCipherSuite: TLSCipherSuiteCore {
        switch self {
        case .tls_aes_128_gcm_sha256:
            return .aes128GCMSHA256
        case .tls_aes_256_gcm_sha384:
            return .aes256GCMSHA384
        case .tls_chacha20_poly1305_sha256:
            return .chacha20Poly1305SHA256
        }
    }
}

// MARK: - TLS Key Schedule

/// Manages TLS 1.3 key derivation (host adapter over ``TLSKeyScheduleCore``).
public struct TLSKeySchedule: Sendable {

    /// The Embedded-clean key schedule, specialised at the host provider.
    private var core: TLSKeyScheduleCore<QUICCryptoProvider>

    /// The negotiated cipher suite.
    public let cipherSuite: CipherSuite

    /// Hash length (32 for SHA-256, 48 for SHA-384).
    public let hashLength: Int

    // MARK: - Initialization

    /// Creates a new key schedule
    /// - Parameter cipherSuite: The negotiated cipher suite
    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        self.cipherSuite = cipherSuite
        self.hashLength = cipherSuite.hashLength
        self.core = TLSKeyScheduleCore(cipherSuite: cipherSuite.coreCipherSuite)
    }

    /// The underlying Embedded-clean key-schedule core.
    ///
    /// Exposed so the QUICCrypto adapter can hand the running key-schedule state
    /// (already at the handshake-secret stage) to the Embedded-clean handshake FSM
    /// (`QUICClientAuthMachine`) and read it back after the FSM derives the
    /// application/exporter/resumption secrets. The core is a value type.
    var coreValue: TLSKeyScheduleCore<QUICCryptoProvider> {
        get { core }
        set { core = newValue }
    }

    // MARK: - Early Secret

    /// Derive early secret from PSK (or use 0 for non-PSK mode)
    /// - Parameter psk: Pre-shared key, or nil for non-PSK mode
    public mutating func deriveEarlySecret(psk: SymmetricKey? = nil) {
        let pskBytes = psk.map { $0.withUnsafeBytes { [UInt8]($0) } }
        core.deriveEarlySecret(psk: pskBytes)
    }

    // MARK: - Handshake Secret

    /// Derive handshake secrets from (EC)DHE shared secret
    /// - Parameters:
    ///   - sharedSecret: The (EC)DHE shared secret
    ///   - transcriptHash: Hash of ClientHello...ServerHello
    /// - Returns: (client_handshake_traffic_secret, server_handshake_traffic_secret)
    public mutating func deriveHandshakeSecrets(
        sharedSecret: SharedSecret,
        transcriptHash: Data
    ) throws -> (client: SymmetricKey, server: SymmetricKey) {
        let secretBytes = sharedSecret.withUnsafeBytes { [UInt8]($0) }
        let (client, server) = try core.deriveHandshakeSecrets(
            sharedSecret: secretBytes,
            transcriptHash: [UInt8](transcriptHash)
        )
        return (SymmetricKey(data: client), SymmetricKey(data: server))
    }

    // MARK: - Application Secret

    /// Derive application (1-RTT) secrets
    /// - Parameter transcriptHash: Hash of ClientHello...server Finished
    /// - Returns: (client_application_traffic_secret_0, server_application_traffic_secret_0)
    public mutating func deriveApplicationSecrets(
        transcriptHash: Data
    ) throws -> (client: SymmetricKey, server: SymmetricKey) {
        let (client, server) = try core.deriveApplicationSecrets(
            transcriptHash: [UInt8](transcriptHash)
        )
        return (SymmetricKey(data: client), SymmetricKey(data: server))
    }

    // MARK: - Key Update

    /// Next application traffic secret (for key update)
    /// - Parameter currentSecret: The current application traffic secret
    /// - Returns: The next application traffic secret
    public func nextApplicationSecret(
        from currentSecret: SymmetricKey
    ) -> SymmetricKey {
        do {
            let next = try core.nextApplicationSecret(from: currentSecret.bytes)
            return SymmetricKey(data: next)
        } catch {
            // "traffic upd" expands to Hash.length (<=48), never exceeding
            // 255*HashLen, so this is unreachable; surface explicitly rather than
            // fabricate a secret (no silent fallback).
            preconditionFailure("nextApplicationSecret HKDF-Expand-Label failed: \(error)")
        }
    }

    // MARK: - Finished Key

    /// The finished key derived from a base key
    /// - Parameter baseKey: The handshake traffic secret
    /// - Returns: The finished key
    public func finishedKey(from baseKey: SymmetricKey) -> SymmetricKey {
        do {
            let key = try core.finishedKey(from: baseKey.bytes)
            return SymmetricKey(data: key)
        } catch {
            // "finished" expands to Hash.length (<=48), never exceeding 255*HashLen,
            // so this is unreachable; surface explicitly rather than fabricate a key
            // (no silent fallback).
            preconditionFailure("finishedKey HKDF-Expand-Label failed: \(error)")
        }
    }

    /// The finished verify_data
    /// - Parameters:
    ///   - key: The finished key
    ///   - transcriptHash: The transcript hash up to the Finished message
    /// - Returns: The verify_data for the Finished message
    public func finishedVerifyData(
        forKey key: SymmetricKey,
        transcriptHash: Data
    ) -> Data {
        Data(core.finishedVerifyData(forKey: key.bytes, transcriptHash: [UInt8](transcriptHash)))
    }

    // MARK: - Exporter Master Secret

    /// Derive the exporter master secret
    /// - Parameter transcriptHash: Hash of ClientHello...server Finished
    /// - Returns: The exporter master secret
    public func deriveExporterMasterSecret(transcriptHash: Data) throws -> SymmetricKey {
        let secret = try core.deriveExporterMasterSecret(transcriptHash: [UInt8](transcriptHash))
        return SymmetricKey(data: secret)
    }

    // MARK: - Resumption Master Secret

    /// Derive the resumption master secret
    /// - Parameter transcriptHash: Hash of ClientHello...client Finished
    /// - Returns: The resumption master secret (for deriving PSKs)
    public func deriveResumptionMasterSecret(transcriptHash: Data) throws -> SymmetricKey {
        let secret = try core.deriveResumptionMasterSecret(transcriptHash: [UInt8](transcriptHash))
        return SymmetricKey(data: secret)
    }

    /// Derive a resumption PSK from the resumption master secret and ticket nonce
    /// - Parameters:
    ///   - resumptionMasterSecret: The resumption master secret
    ///   - ticketNonce: The ticket nonce from NewSessionTicket
    /// - Returns: The PSK for use in future connections
    public func deriveResumptionPSK(
        resumptionMasterSecret: SymmetricKey,
        ticketNonce: Data
    ) -> SymmetricKey {
        do {
            let psk = try core.deriveResumptionPSK(
                resumptionMasterSecret: resumptionMasterSecret.bytes,
                ticketNonce: [UInt8](ticketNonce)
            )
            return SymmetricKey(data: psk)
        } catch {
            // "resumption" expands to Hash.length (<=48), never exceeding 255*HashLen,
            // so this is unreachable; surface explicitly rather than fabricate a PSK
            // (no silent fallback).
            preconditionFailure("deriveResumptionPSK HKDF-Expand-Label failed: \(error)")
        }
    }

    // MARK: - PSK/Early Secrets

    /// Derive the binder key from the early secret
    /// - Parameters:
    ///   - isResumption: true for resumption PSK (res binder), false for external PSK (ext binder)
    /// - Returns: The binder key for computing PSK binders
    public func deriveBinderKey(isResumption: Bool) throws -> SymmetricKey {
        let key = try core.deriveBinderKey(isResumption: isResumption)
        return SymmetricKey(data: key)
    }

    /// Derive the client early traffic secret (for 0-RTT)
    /// - Parameter transcriptHash: Hash of ClientHello
    /// - Returns: The client early traffic secret
    public func deriveClientEarlyTrafficSecret(transcriptHash: Data) throws -> SymmetricKey {
        let secret = try core.deriveClientEarlyTrafficSecret(transcriptHash: [UInt8](transcriptHash))
        return SymmetricKey(data: secret)
    }

    /// Derive the early exporter master secret
    /// - Parameter transcriptHash: Hash of ClientHello
    /// - Returns: The early exporter master secret
    public func deriveEarlyExporterMasterSecret(transcriptHash: Data) throws -> SymmetricKey {
        let secret = try core.deriveEarlyExporterMasterSecret(transcriptHash: [UInt8](transcriptHash))
        return SymmetricKey(data: secret)
    }

    /// The current early secret (for PSK-related computations)
    public func currentEarlySecret() throws -> SymmetricKey {
        let secret = try core.currentEarlySecret()
        return SymmetricKey(data: secret)
    }
}

// MARK: - SymmetricKey bytes helper

extension SymmetricKey {
    /// The raw key bytes (host-only bridge for the `[UInt8]`-based core).
    fileprivate var bytes: [UInt8] {
        withUnsafeBytes { [UInt8]($0) }
    }
}

// MARK: - Traffic Keys

/// Traffic keys derived from a traffic secret
public struct TrafficKeys: Sendable {
    /// The encryption key
    public let key: SymmetricKey

    /// The IV
    public let iv: Data

    /// Derives traffic keys from a traffic secret
    /// - Parameters:
    ///   - secret: The traffic secret
    ///   - cipherSuite: The negotiated cipher suite (for hash function selection)
    ///   - keyLength: Key length in bytes (16 for AES-128, 32 for AES-256)
    ///   - ivLength: IV length in bytes (always 12 for TLS 1.3)
    public init(
        secret: SymmetricKey,
        cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256,
        keyLength: Int = 16,
        ivLength: Int = 12
    ) {
        // key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        let suite = TLSCipherSuiteCore(
            hash: cipherSuite.coreCipherSuite.hash,
            keyLength: keyLength,
            ivLength: ivLength
        )
        let secretBytes = secret.withUnsafeBytes { [UInt8]($0) }
        do {
            let (keyBytes, ivBytes) = try TLSKeyScheduleCore<QUICCryptoProvider>.trafficKeys(
                secret: secretBytes,
                cipherSuite: suite
            )
            self.key = SymmetricKey(data: keyBytes)
            self.iv = Data(ivBytes)
        } catch {
            // HKDF-Expand-Label length bounds for TLS 1.3 key/iv (<=48) never exceed
            // 255*HashLen, so this path is unreachable; surface explicitly rather than
            // fabricate a key (no silent fallback).
            preconditionFailure("TrafficKeys HKDF-Expand-Label failed: \(error)")
        }
    }
}
