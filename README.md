# Syntecxhub_Secure_File_Transfer

[![CI](https://github.com/DevRisny/Syntecxhub_Secure_File_Transfer/actions/workflows/ci.yml/badge.svg)](https://github.com/DevRisny/Syntecxhub_Secure_File_Transfer/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Crypto](https://img.shields.io/badge/crypto-X25519%20%2B%20AES--256--GCM-blue)

Week 2, Task 4 of the **Syntecxhub Cyber Security Internship**: **encrypted file upload and download** between a client and server, with chunking, integrity checks, resume support and files stored encrypted on disk — the server never holds a file's plaintext or its key. See [SECURITY.md](SECURITY.md) for the full threat model and design reasoning (including a real nonce-reuse bug the tests caught during resume).

## Task checklist
| Requirement | Where |
|---|---|
| Encrypted upload/download, client & server (AES + secure channel) | `transport.py` (X25519 + PSK handshake, AES-256-GCM channel) + `filecrypto.py` (per-file AES-256-GCM) |
| Chunk large files | `filecrypto.encrypt_file` / `client.py` — configurable chunk size |
| Integrity checks (HMAC) | Per-chunk AES-GCM tag **and** an independent whole-file HMAC-SHA256, verified after reassembly |
| Resume support | `client.py` resume sidecar + `storage.py` idempotent chunk writes; a real interrupted transfer is covered by a test |
| Store files encrypted on server disk, safe retrieval | `storage.py` — stores/relays ciphertext only, filename allow-listed against path traversal |
| Threat model discussion (MITM, key management) | [SECURITY.md](SECURITY.md) |

## Quick start
```bash
pip install .                              # installs `sft-server` and `sft`
export SYNTECXHUB_SFT_PASSPHRASE="correct horse battery staple"

sft-server --port 6000 --storage ./storage   # terminal 1
sft --port 6000 upload myfile.pdf            # terminal 2
sft --port 6000 list
sft --port 6000 download myfile.pdf myfile_out.pdf
```

### Example (real output)
```
$ sft --port 6055 upload bigfile.bin
Uploading 8/8 chunks (100%)
Uploaded 'bigfile.bin' as 'bigfile.bin'.

$ sft --port 6055 download bigfile.bin bigfile_out.bin
Downloading 8/8 chunks (100%)
Downloaded 'bigfile.bin' -> 'bigfile_out.bin' (integrity verified).

$ cmp bigfile.bin bigfile_out.bin && echo identical
identical

$ SYNTECXHUB_SFT_PASSPHRASE="wrong" sft --port 6055 list
Error: handshake failed: wrong passphrase or not an SFT server
```

## How it works
```
 client                                                        server
   | ---- X25519 handshake + passphrase auth (as in Encrypted Chat) ----- |
   |                                                                      |
   | upload_begin {salt, hmac, chunk_count} ---------------------------> |  resumes or
   | <----------------------------------------- resume_info {next_chunk} |  starts fresh
   | ---- chunk[i] = AES-256-GCM(file_key, nonce=i, plaintext[i]) -----> |  stored as-is,
   | ---- ... ------------------------------------------------------->  |  never decrypted
   | upload_end ---------------------------------------------------->   |  verify count
   | <------------------------------------------------------------ ack  |
```
1. **Transport handshake.** Fresh X25519 keys per connection, authenticated with the shared passphrase — protects every message (control and data) against a network attacker.
2. **File key.** Derived from the passphrase + a random salt generated for *this file*. The server is told the salt (so a downloader can rederive the same key) but never the key itself.
3. **Chunking.** The file is split and each chunk is independently AES-256-GCM encrypted, nonce = chunk index (unique per file because the key is unique per file).
4. **Resume.** The client keeps a small local sidecar with the file's salt/HMAC; the server reports how many chunks it already has for that exact (filename, salt, HMAC), and the client continues from there — re-using the correct nonce for each resumed chunk.
5. **Integrity.** Every chunk is authenticated by its own GCM tag. After a full download, an independent HMAC-SHA256 over the whole reassembled file is checked against the value the uploader sent — catches a dropped or duplicated chunk that individual tags alone wouldn't.

## Project layout
```
src/syntecxhub_sft/
  transport.py   X25519 handshake, passphrase auth, AES-256-GCM transport channel
  filecrypto.py  file key derivation, per-chunk AES-GCM, whole-file HMAC
  protocol.py    JSON control messages + compact binary chunk framing
  storage.py     server-side ciphertext-only storage, resume bookkeeping, path-safety
  server.py      asyncio server
  client.py      FileTransferClient (upload/download/list/delete, resume)
  cli.py         `sft` command
tests/           53 tests
```

## Tests
```bash
pip install -e . ruff
python -m unittest discover -s tests -v
ruff check . && ruff format --check .
```
Includes real end-to-end tests: a live local server + client over real sockets, a network sniffer test (no filename, file content, or passphrase appears in the captured bytes), a tampered-stored-chunk detection test, and a genuinely interrupted upload (connection closed mid-transfer) that reconnects and resumes correctly.

## Limits (honest notes)
See [SECURITY.md](SECURITY.md) — in short: one shared passphrase (not per-user accounts), filenames/sizes are visible to the server even though content isn't, and this hasn't had a professional security audit.

## What I learned
Defense in depth (two independent encryption layers for two different threats), key derivation and domain separation (scrypt + HKDF with different salts for different purposes), safe nonce management across a resumable protocol (and a real bug it would have caused), authenticated encryption vs. whole-message integrity, and designing storage that stays useless to its own operator.
