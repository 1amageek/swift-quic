import QUICWire

/// Fixed storage for QUIC's closed set of encryption levels.
///
/// This avoids hashing, allocation, and dictionary metadata on the packet path.
struct EncryptionLevelSlots<Value: Sendable>: Sendable {
    private var initial: Value?
    private var zeroRTT: Value?
    private var handshake: Value?
    private var application: Value?

    subscript(level: EncryptionLevel) -> Value? {
        get {
            switch level {
            case .initial: initial
            case .zeroRTT: zeroRTT
            case .handshake: handshake
            case .application: application
            }
        }
        set {
            switch level {
            case .initial: initial = newValue
            case .zeroRTT: zeroRTT = newValue
            case .handshake: handshake = newValue
            case .application: application = newValue
            }
        }
    }

    mutating func take(_ level: EncryptionLevel) -> Value? {
        let value = self[level]
        self[level] = nil
        return value
    }
}
