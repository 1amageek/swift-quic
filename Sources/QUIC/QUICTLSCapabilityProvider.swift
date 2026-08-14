import QUICTLS

/// Resolves TLS operations that are intentionally suspended outside the
/// synchronous handshake state machine, such as trust, credential selection,
/// and signing backed by an external key owner.
public protocol QUICTLSCapabilityProviding: Sendable {
    func response(
        to request: TLS13CapabilityRequest
    ) async throws(QUICTLSCapabilityError) -> TLS13CapabilityResponse
}

/// Fail-closed provider for handshakes whose configured swift-tls mechanisms do
/// not require an external capability. If such a request is emitted, the
/// connection reports a typed error instead of accepting it implicitly.
public struct NoExternalQUICTLSCapabilities: QUICTLSCapabilityProviding {
    public init() {}

    public func response(
        to request: TLS13CapabilityRequest
    ) async throws(QUICTLSCapabilityError) -> TLS13CapabilityResponse {
        _ = request
        throw .unavailable
    }
}
