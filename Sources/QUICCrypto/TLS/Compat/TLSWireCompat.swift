/// Shared `Data`-boundary glue for the moved TLS handshake wire types.
///
/// The Embedded-clean cores in `QUICTLSCore` throw the closed ``TLSWireError``
/// and operate on `[UInt8]`. This file maps that typed error back to the
/// historical adapter errors (``TLSDecodeError`` / ``TLSHandshakeError``) so
/// existing call sites and tests observe the same error surface, and provides the
/// non-throwing `encode() -> Data` trap helper used by the per-type `Data` shims.
///
/// Foundation-only adapter glue.

import Foundation
import QUICTLSCore

// MARK: - TLSWireError mapping

extension TLSWireError {
    /// Maps the core's typed ``TLSWireError`` back to the historical adapter
    /// error surface. Most cases map to ``TLSDecodeError``; the
    /// `handshakeDecodeError` case (raised by the manual-offset
    /// ``CertificateRequest`` parser) maps to ``TLSHandshakeError/decodeError(_:)``
    /// so the unchanged `#expect(throws: TLSHandshakeError.self)` tests still pass.
    func mappedAdapterError() -> any Error {
        switch self {
        case .insufficientData(let expected, let actual):
            return TLSDecodeError.insufficientData(expected: expected, actual: actual)
        case .unknownHandshakeType(let byte):
            return TLSDecodeError.unknownHandshakeType(byte)
        case .invalidFormat(let reason):
            return TLSDecodeError.invalidFormat(reason)
        case .unsupportedVersion(let version):
            return TLSDecodeError.unsupportedVersion(version)
        case .handshakeDecodeError(let reason):
            return TLSHandshakeError.decodeError(reason)
        case .bytes(let byteError):
            // A lower-level read overflow surfaces as a decode error rather than a
            // fabricated fallback, so no information is silently dropped.
            return TLSDecodeError.invalidFormat("byte codec error: \(byteError)")
        }
    }

    /// Rethrows the mapped adapter error. Returns `Never`: the `do { ... } catch`
    /// shim recipe calls this so the typed-throws core failure is re-surfaced as
    /// the historical untyped adapter error at the `Data` boundary.
    func rethrowUnwrapped() throws -> Never {
        throw mappedAdapterError()
    }
}

extension Error {
    /// Convenience for the `catch { try error.rethrowUnwrapped() }` recipe used by
    /// the `Data` decode shims. When the caught error is a ``TLSWireError`` it is
    /// mapped to the historical adapter error; otherwise it is rethrown as-is.
    func rethrowUnwrapped() throws -> Never {
        if let wireError = self as? TLSWireError {
            try wireError.rethrowUnwrapped()
        }
        throw self
    }
}

// MARK: - Encode helper

/// Runs a throwing byte encoder and returns `Data`, trapping on the
/// impossible-for-valid-input wire-length overflow.
///
/// The pre-extraction `Data`-based writers expressed an unencodable message (a
/// payload exceeding its length-prefix width) as an integer-conversion trap; we
/// preserve that loud, non-silent crash here rather than swallowing the error —
/// there is no valid fallback for an unencodable message.
@inline(__always)
func tlsEncodeData(_ body: () throws -> [UInt8]) -> Data {
    do {
        return Data(try body())
    } catch {
        fatalError("TLS wire encoding exceeded a length bound: \(error)")
    }
}
