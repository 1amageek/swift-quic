/// QUIC Transport Parameter IDs (RFC 9000 Section 18.2) — host adapter alias.
///
/// The identifier enum is defined Embedded-clean as
/// ``TransportParameterIDCore`` in `QUICConnectionCore`. The adapter re-exposes
/// it under the historical `TransportParameterID` name so existing call sites
/// and tests are unchanged.

import QUICConnectionCore

/// QUIC Transport Parameter IDs (RFC 9000 Section 18.2)
public typealias TransportParameterID = TransportParameterIDCore
