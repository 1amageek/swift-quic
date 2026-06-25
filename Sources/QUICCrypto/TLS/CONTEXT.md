# QUICCrypto/TLS — CONTEXT
Scope/role: the host TLS 1.3 handshake adapter (`TLS13Handler`, RFC 8446 + RFC 9001 integration); thin layer over the `QUICTLSCore` FSMs and key schedule.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing the handshake FSM, the keys-available output, or PSK resumption.
`TLS13Handler` is a host adapter; the TLS 1.3 logic (FSMs, key schedule,
transcript hash, message/extension wire codecs) lives in the Embedded-clean
`QUICTLSCore`, generic over `C: CryptoProvider`. This adapter specialises it at
`C = QUICCryptoProvider` and bridges `Data` / `SymmetricKey`.

## Contracts (the load-bearing rules)

- **The FSMs and key schedule live in `QUICTLSCore`.** `TLSKeyScheduleCore`
  (early/handshake/master secrets, HKDF-Expand-Label, Derive-Secret, traffic
  secrets, finished key / verify-data, RFC 8446 §7.1), `TLSTranscriptHashCore`,
  and `QUICClientHandshake` / `QUICServerHandshake` / `QUICClientAuthMachine`. Do
  not reimplement them here.
- **`KeysAvailableInfo` MUST carry the negotiated cipher suite.** Without
  `cipherSuite`, the packet-protection layer cannot select the correct AEAD. Every
  `.keysAvailable` output sets it from the negotiated suite. The TLS↔QUIC suite
  mapping must be exact (ChaCha20-Poly1305-SHA256, AES-128-GCM-SHA256;
  AES-256-GCM-SHA384 maps with SHA-384 as the hash).
- **Signing/verification is injected via the seam** (`TLSSignatureSigner` /
  `TLSSignatureVerifier` in the core); this adapter supplies the host
  swift-certificates / swift-crypto implementation.

## Invariants (must hold; tests guard them)

- **Fail-closed peer authentication.** CertificateVerify is always verified; a
  server cannot skip Certificate/CertificateVerify, and Finished is accepted only
  after authentication completes. There is no silent fallback to an
  unauthenticated channel (RFC 8446 §4.4.3).
- **PSK resumption preserves `ticketNonce`.** `StoredSession` must keep the
  ticket nonce — it is required to derive the PSK; a placeholder must not be used
  during resumption validation.
- **The binder transcript hash is selected by the session's cipher suite**
  (SHA-384 for AES-256-GCM-SHA384, else SHA-256), never hardcoded to SHA-256.
- **0-RTT early data is replay-protected**; the early-data path uses the
  resumption secret and the recorded `maxEarlyDataSize`.

## Embedded constraints (do not regress)

- `QUICTLSCore` stays Embedded-clean: no Foundation, no `any`, no `Mutex`, no
  direct crypto. The host X.509 / Foundation surface (swift-certificates) lives in
  this adapter so the core needs neither.

## Wire protocol notes

- Handshake messages and extensions are wire-coded in `QUICTLSCore`: ClientHello,
  ServerHello, Certificate, CertificateVerify, Finished, NewSessionTicket, and the
  TLS extensions (RFC 8446 §4 / §4.2).

## Build

- Host: `swift build` / `swift test --filter TLSTests` (the underlying
  `QUICTLSCore` is part of the Embedded compile).
