/// QUICCore — Foundation adapter over the Embedded-clean ``QUICCoreCodec``.
///
/// `QUICCoreCodec` owns the canonical QUIC wire codec (varint, frame codec,
/// packet-header codec) over `[UInt8]` / `P2PCoreBytes` `ByteReader`/`ByteWriter`,
/// with no Foundation, no `any` existentials, and typed throws. This adapter
/// re-exports those types and restores the historical `Data`-based public API
/// (the `Compat/` layer) so existing call sites and the test suite compile
/// unchanged. The not-yet-Embedded files (packet protection codec, coalesced
/// packet assembly, qlog, transport parameters, the `Error?`-bearing
/// `QUICError`) stay in this Foundation target.

@_exported import QUICCoreCodec
