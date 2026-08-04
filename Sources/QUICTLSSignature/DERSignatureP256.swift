// DERSignatureP256.swift
//
// Compatibility spelling for the TLS-facing P-256 signature capability.
// `SSLBackendP256Signature` already returns the RFC 8446 DER encoding, so a
// second wrapper would encode an already encoded signature and corrupt the
// handshake. The canonical backend is the single implementation.

import P2PCrypto

/// TLS P-256 ECDSA signatures encoded as DER `SEQUENCE { INTEGER r, INTEGER s }`.
public typealias DERSignatureP256 = DefaultCryptoProvider.P256Signature
