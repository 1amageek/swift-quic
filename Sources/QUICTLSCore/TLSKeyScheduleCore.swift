/// TLS 1.3 key schedule (RFC 8446 §7.1), Embedded-clean and generic over
/// `C: CryptoProvider`.
///
/// Derives the early / handshake / master secrets and every traffic / finished /
/// exporter / resumption secret over the `CryptoProvider` seam (HKDF via
/// `C.HKDFSHA256` / `C.HKDFSHA384`, SHA via `C.SHA256` / `C.SHA384`, finished MAC via
/// `C.HMACSHA256` / `C.HMACSHA384`). All secrets are raw `[UInt8]`; there is no
/// `SymmetricKey` / `SharedSecret` here — the QUICCrypto adapter bridges those.
///
/// The derivation order, labels, and `HkdfLabel` byte layout are kept byte-identical
/// to the swift-crypto path so existing RFC vectors pass through the seam unchanged.
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
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, no Mutex. Typed throws
/// (closed ``TLSKeyScheduleError``); the state machine is value-typed and the
/// QUICCrypto adapter holds it under its own Mutex.
import P2PCoreBytes
import P2PCoreCrypto

/// The TLS 1.3 key schedule over the crypto seam.
public struct TLSKeyScheduleCore<C: CryptoProvider>: Sendable {

    /// The current secret in the schedule.
    private enum State: Sendable {
        case initial
        case earlySecret([UInt8])
        case handshakeSecret([UInt8])
        case masterSecret([UInt8])
    }

    private var state: State

    /// The negotiated cipher suite (drives the hash function and key/iv lengths).
    public let cipherSuite: TLSCipherSuiteCore

    /// Hash output length in bytes (32 for SHA-256, 48 for SHA-384).
    public var hashLength: Int { cipherSuite.hashLength }

    private var hash: TLSHashAlgorithm { cipherSuite.hash }

    // MARK: - Initialization

    /// Creates a key schedule for the given cipher suite (default AES-128-GCM-SHA256).
    public init(cipherSuite: TLSCipherSuiteCore = .aes128GCMSHA256) {
        self.state = .initial
        self.cipherSuite = cipherSuite
    }

    // MARK: - Early Secret

    /// `early_secret = HKDF-Extract(0, PSK)` (PSK = zeros in non-PSK mode).
    public mutating func deriveEarlySecret(psk: [UInt8]? = nil) {
        let ikm = psk ?? [UInt8](repeating: 0, count: hashLength)
        let salt = [UInt8](repeating: 0, count: hashLength)
        state = .earlySecret(TLSExpandLabel<C>.extract(salt: salt, ikm: ikm, hash: hash))
    }

    // MARK: - Handshake Secret

    /// Derives `handshake_secret` from the (EC)DHE shared secret and returns the
    /// client/server handshake traffic secrets (`"c hs traffic"` / `"s hs traffic"`
    /// over `CH...SH`).
    ///
    /// If the schedule is still `.initial`, the (zero-PSK) early secret is derived
    /// first; calling past the early-secret stage throws ``TLSKeyScheduleError``.
    public mutating func deriveHandshakeSecrets(
        sharedSecret: [UInt8],
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> (client: [UInt8], server: [UInt8]) {
        switch state {
        case .initial:
            deriveEarlySecret(psk: nil)
        case .earlySecret:
            break
        case .handshakeSecret, .masterSecret:
            throw .invalidState(.earlySecret)
        }

        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState(.earlySecret)
        }

        // Derive-Secret(early_secret, "derived", "") with the empty-string transcript.
        let derivedSecret = try TLSExpandLabel<C>.deriveSecret(
            secret: earlySecret,
            label: "derived",
            transcriptHash: TLSExpandLabel<C>.emptyTranscriptHash(hash: hash),
            hash: hash
        )

        // HKDF-Extract(derived_secret, shared_secret).
        let handshakeSecret = TLSExpandLabel<C>.extract(
            salt: derivedSecret,
            ikm: sharedSecret,
            hash: hash
        )
        state = .handshakeSecret(handshakeSecret)

        let clientSecret = try TLSExpandLabel<C>.deriveSecret(
            secret: handshakeSecret, label: "c hs traffic", transcriptHash: transcriptHash, hash: hash)
        let serverSecret = try TLSExpandLabel<C>.deriveSecret(
            secret: handshakeSecret, label: "s hs traffic", transcriptHash: transcriptHash, hash: hash)
        return (client: clientSecret, server: serverSecret)
    }

    // MARK: - Application Secret

    /// Derives `master_secret` and returns the client/server application (1-RTT)
    /// traffic secrets (`"c ap traffic"` / `"s ap traffic"` over `CH...SF`).
    public mutating func deriveApplicationSecrets(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> (client: [UInt8], server: [UInt8]) {
        guard case .handshakeSecret(let handshakeSecret) = state else {
            throw .invalidState(.handshakeSecret)
        }

        // Derive-Secret(handshake_secret, "derived", "").
        let derivedSecret = try TLSExpandLabel<C>.deriveSecret(
            secret: handshakeSecret,
            label: "derived",
            transcriptHash: TLSExpandLabel<C>.emptyTranscriptHash(hash: hash),
            hash: hash
        )

        // HKDF-Extract(derived_secret, 0).
        let masterSecret = TLSExpandLabel<C>.extract(
            salt: derivedSecret,
            ikm: [UInt8](repeating: 0, count: hashLength),
            hash: hash
        )
        state = .masterSecret(masterSecret)

        let clientSecret = try TLSExpandLabel<C>.deriveSecret(
            secret: masterSecret, label: "c ap traffic", transcriptHash: transcriptHash, hash: hash)
        let serverSecret = try TLSExpandLabel<C>.deriveSecret(
            secret: masterSecret, label: "s ap traffic", transcriptHash: transcriptHash, hash: hash)
        return (client: clientSecret, server: serverSecret)
    }

    // MARK: - Key Update

    /// `application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)`.
    public func nextApplicationSecret(from currentSecret: [UInt8]) throws(TLSKeyScheduleError) -> [UInt8] {
        try TLSExpandLabel<C>.expandLabel(
            secret: currentSecret, label: "traffic upd", context: [], length: hashLength, hash: hash)
    }

    // MARK: - Finished Key

    /// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)`.
    public func finishedKey(from baseKey: [UInt8]) throws(TLSKeyScheduleError) -> [UInt8] {
        try TLSExpandLabel<C>.expandLabel(
            secret: baseKey, label: "finished", context: [], length: hashLength, hash: hash)
    }

    /// `verify_data = HMAC(finished_key, Transcript-Hash)` using the suite's hash.
    public func finishedVerifyData(forKey key: [UInt8], transcriptHash: [UInt8]) -> [UInt8] {
        switch hash {
        case .sha384:
            return C.HMACSHA384.authenticationCode(for: transcriptHash.span, key: key.span)
        case .sha256:
            return C.HMACSHA256.authenticationCode(for: transcriptHash.span, key: key.span)
        }
    }

    // MARK: - Exporter / Resumption Master Secret

    /// `exporter_master_secret = Derive-Secret(master_secret, "exp master", CH...SF)`.
    public func deriveExporterMasterSecret(transcriptHash: [UInt8]) throws(TLSKeyScheduleError) -> [UInt8] {
        guard case .masterSecret(let masterSecret) = state else {
            throw .invalidState(.masterSecret)
        }
        return try TLSExpandLabel<C>.deriveSecret(
            secret: masterSecret, label: "exp master", transcriptHash: transcriptHash, hash: hash)
    }

    /// `resumption_master_secret = Derive-Secret(master_secret, "res master", CH...CF)`.
    public func deriveResumptionMasterSecret(transcriptHash: [UInt8]) throws(TLSKeyScheduleError) -> [UInt8] {
        guard case .masterSecret(let masterSecret) = state else {
            throw .invalidState(.masterSecret)
        }
        return try TLSExpandLabel<C>.deriveSecret(
            secret: masterSecret, label: "res master", transcriptHash: transcriptHash, hash: hash)
    }

    /// `PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`.
    public func deriveResumptionPSK(
        resumptionMasterSecret: [UInt8],
        ticketNonce: [UInt8]
    ) throws(TLSKeyScheduleError) -> [UInt8] {
        try TLSExpandLabel<C>.expandLabel(
            secret: resumptionMasterSecret,
            label: "resumption",
            context: ticketNonce,
            length: hashLength,
            hash: hash
        )
    }

    // MARK: - PSK / Early Secrets

    /// `binder_key = Derive-Secret(early_secret, "res binder" / "ext binder", "")`.
    public func deriveBinderKey(isResumption: Bool) throws(TLSKeyScheduleError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState(.earlySecret)
        }
        let label = isResumption ? "res binder" : "ext binder"
        return try TLSExpandLabel<C>.deriveSecret(
            secret: earlySecret,
            label: label,
            transcriptHash: TLSExpandLabel<C>.emptyTranscriptHash(hash: hash),
            hash: hash
        )
    }

    /// `client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)`.
    public func deriveClientEarlyTrafficSecret(transcriptHash: [UInt8]) throws(TLSKeyScheduleError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState(.earlySecret)
        }
        return try TLSExpandLabel<C>.deriveSecret(
            secret: earlySecret, label: "c e traffic", transcriptHash: transcriptHash, hash: hash)
    }

    /// `early_exporter_master_secret = Derive-Secret(early_secret, "e exp master", ClientHello)`.
    public func deriveEarlyExporterMasterSecret(transcriptHash: [UInt8]) throws(TLSKeyScheduleError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState(.earlySecret)
        }
        return try TLSExpandLabel<C>.deriveSecret(
            secret: earlySecret, label: "e exp master", transcriptHash: transcriptHash, hash: hash)
    }

    /// The current early secret (for PSK-related computations).
    public func currentEarlySecret() throws(TLSKeyScheduleError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState(.earlySecret)
        }
        return earlySecret
    }

    // MARK: - Traffic Keys

    /// Derives the AEAD `(key, iv)` from a traffic secret (RFC 8446 §7.3):
    /// - `key = HKDF-Expand-Label(secret, "key", "", key_length)`
    /// - `iv  = HKDF-Expand-Label(secret, "iv",  "", iv_length)`
    public static func trafficKeys(
        secret: [UInt8],
        cipherSuite: TLSCipherSuiteCore
    ) throws(TLSKeyScheduleError) -> (key: [UInt8], iv: [UInt8]) {
        let key = try TLSExpandLabel<C>.expandLabel(
            secret: secret, label: "key", context: [], length: cipherSuite.keyLength, hash: cipherSuite.hash)
        let iv = try TLSExpandLabel<C>.expandLabel(
            secret: secret, label: "iv", context: [], length: cipherSuite.ivLength, hash: cipherSuite.hash)
        return (key: key, iv: iv)
    }
}
