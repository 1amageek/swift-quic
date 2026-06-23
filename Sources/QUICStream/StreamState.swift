/// QUIC Stream State Machine
///
/// The stream FSM value types — `StreamID`, `SendState`, `RecvState`, `StreamState` —
/// now live in the Embedded-clean `QUICStreamCore` target. This file re-exports them
/// so existing call sites and the test suite that reference `QUICStream` symbols keep
/// compiling unchanged.

@_exported import QUICStreamCore
