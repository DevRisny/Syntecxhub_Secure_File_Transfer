# Changelog

## 1.0.0
- Transport security: ephemeral X25519 key exchange + passphrase authentication (same
  design as the Encrypted Chat project), AES-256-GCM with counter nonces, replay protection
- File-level security (second, independent layer): file key + HMAC key derived from the
  passphrase and a random per-file salt via scrypt + HKDF — the server never computes or
  sees this key
- Chunked upload/download (AES-256-GCM per chunk) with a whole-file HMAC-SHA256 integrity
  check after reassembly
- Resume support: interrupted uploads continue from the last stored chunk, matched by
  salt/HMAC, with a local resume sidecar file and idempotent chunk writes on the server
- Zero-knowledge server storage: the server stores and relays ciphertext only
- `sft-server` and `sft` (upload/download/list/delete) console commands
- 53 unit and integration tests (including a network sniffer test, a tampered-chunk
  detection test, and a real interrupted-and-resumed transfer test)
- ruff lint and format checks, GitHub Actions CI on Python 3.9 to 3.13
