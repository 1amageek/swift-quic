# QUICCrypto — CONTEXT
Scope/role: the host (Foundation) packet-protection + TLS adapter (RFC 9001); thin layer over `QUICPacketProtectionCore` + `QUICTLSCore`, specialised at `C = QUICCryptoProvider`.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing the cipher-suite flow, header protection, or key derivation. The
cryptographic logic lives in two Embedded-clean cores; this module is the host
adapter that specialises them at `C = QUICCryptoProvider` (the unified
`DefaultCryptoProvider`, except ECDSA is DER-encoded for the TLS path) and bridges
`Data` / `SymmetricKey` / `SharedSecret`.

## Contracts (the load-bearing rules)

- **All crypto routes through the seam.** `PacketProtector<C, A>`
  (`QUICPacketProtectionCore`) performs AEAD seal/open + header protection over the
  `CryptoProvider` / `HeaderProtectionProvider` seam. Header protection is NOT a
  CommonCrypto-direct call — the AES-ECB and ChaCha20 block masks come from
  `QUICCryptoProvider.HeaderProtection` (host swift-crypto / Embedded BoringSSL).
  Do not add a direct-crypto shortcut.
- **Cipher-suite dispatch is `SuiteProtector<C>`** (closed enum over
  `PacketProtector<C, A>`), not `any PacketOpener` / `any PacketSealer`. It is the
  thing that replaced those existentials.
- **The negotiated cipher suite MUST propagate from TLS to packet protection.**
  `TLS13Handler` puts it in `KeysAvailableInfo.cipherSuite`; key derivation must be
  called WITH that suite, and the protector chosen via the factory. Never default
  to AES-128-GCM when a suite is available — it silently breaks ChaCha20-Poly1305.
- **The TLS 1.3 key schedule lives in `QUICTLSCore`** (`TLSKeyScheduleCore`,
  RFC 8446 §7.1; `TLSTranscriptHashCore`). This adapter bridges it; it does not
  reimplement the schedule.

## Invariants (must hold; tests guard them)

- **Fail-closed peer authentication.** CertificateVerify proof-of-possession is
  always verified when a certificate is presented; certificate trust evaluation
  (EKU serverAuth / SAN / NameConstraints, RFC 5280) is fail-closed. There is no
  silent fallback to an unauthenticated channel.
- **Key derivation uses HKDF-Expand-Label** (RFC 8446 §7.1) with the QUIC labels
  `"quic key"` / `"quic iv"` / `"quic hp"` (RFC 9001 §5.1) and `"quic ku"` for key
  update (§6). The `"tls13 "` prefix is mandatory.
- **AEAD nonce = IV XOR left-padded packet number; AAD = the header through the
  unprotected packet number** (RFC 9001 §5.3). The 16-byte tag is appended.
- **Header protection sample is 16 bytes at `pn_offset + 4`** (RFC 9001 §5.4); the
  mask covers the low 4 bits of a long-header first byte / low 5 bits of a
  short-header first byte. ChaCha20 HP uses sample[0:4] as a little-endian counter
  and sample[4:16] as the nonce (RFC 8439 §2.3).
- **PSK / session resumption preserves `ticketNonce`** in `StoredSession`; the
  binder transcript hash is selected by the session's cipher suite (SHA-384 for
  AES-256-GCM-SHA384, else SHA-256), never always SHA-256.

## Embedded constraints (do not regress)

- The cores (`QUICPacketProtectionCore`, `QUICTLSCore`) stay Embedded-clean: no
  Foundation, no `any`, no `Mutex`, no direct crypto. This adapter holds the
  Foundation/X.509 surface (swift-crypto, swift-certificates) so the cores need
  neither.

## Wire protocol notes

- Supported suites: AES-128-GCM-SHA256 (16-byte key / 12-byte IV / 16-byte HP key)
  and ChaCha20-Poly1305-SHA256 (32-byte key / 12-byte IV / 32-byte HP key); key
  updates may add AES-256-GCM.
- Test vectors: RFC 9001 Appendix A (Initial keys A.1, Handshake A.2, ChaCha20
  short-header A.5).

## Build

- Host: `swift build` / `swift test --filter QUICCryptoTests` (also exercises
  `QUICPacketProtectionCore` + `QUICTLSCore`).
