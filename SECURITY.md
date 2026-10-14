# Security notes / threat model

## Two independent layers of encryption, on purpose
| Layer | Protects against | Key known to |
|---|---|---|
| **Transport** (`transport.py`) | Eavesdropping and tampering on the network while data is in transit; a classic man-in-the-middle during connection setup | Both endpoints for that one connection only (fresh X25519 keys every time) |
| **File** (`filecrypto.py`) | The server itself reading file content, and anyone who later steals the server's disk | Only someone who knows the shared passphrase |

A file is encrypted with a key derived from the **passphrase + a random per-file salt**
*before* the transport layer ever touches it. The server decrypts the transport frames (so
it can read control messages like "here is chunk 7 of file X"), but the chunk payload
inside those messages stays ciphertext end to end — the server's code never calls
`derive_file_keys`. This is why `storage.py` only ever reads and writes raw bytes: it has
no way to decrypt what it stores, even though it's a fully trusted relay for everything
else.

## Threat model
| Threat | Mitigation |
|---|---|
| Network eavesdropper (passive) | Transport layer: AES-256-GCM, fresh keys per connection |
| Man-in-the-middle during handshake | Both sides prove knowledge of the passphrase via an HMAC over the full handshake transcript before any data is exchanged |
| Malicious or compromised server operator | File layer: server never has the file key, so it cannot read uploaded/stored content, only relay ciphertext |
| Stolen server disk / backup | Same as above — stored chunks are useless without the passphrase |
| Tampered chunk (in transit or at rest) | Each chunk has its own AES-GCM authentication tag; `decrypt_chunk` raises `IntegrityError` on any modification |
| Dropped / duplicated / reordered chunks | Chunk index is bound into the nonce and checked on write (filename), and the whole-file HMAC-SHA256 (computed independently of per-chunk tags) is verified after reassembly — catches issues per-chunk tags alone would not |
| Replayed transport frames | Transport-level strictly-increasing counter, same mechanism as the Encrypted Chat project |
| Nonce reuse (fatal for AES-GCM) | File key is unique per upload (fresh random salt every time); nonce = chunk index, which only increases and is tracked explicitly across resumes (see below) |
| Path traversal via filename | `safe_name()` allow-lists characters and rejects `..`; stored files never use the client-supplied name as a literal path |
| Guessing the passphrase from a captured handshake or stolen file | scrypt (cost `2**14`) on both the transport PSK and the file key, each with its own random salt |

## A real bug this design caught, and how
Resuming an upload means re-encrypting the remaining chunks with the **same** per-file key
(derived from the same salt) used for the chunks already sent — so the nonce (the chunk
index) must continue counting up from where the interrupted attempt stopped, never restart
at 0. An early version of `encrypt_file()` always started numbering at 0, which would have
silently reused a nonce whenever a transfer resumed. `tests/test_integration.py`'s
`test_interrupted_upload_resumes_and_matches_original` genuinely interrupts a transfer
(closes the connection before `upload_end`) and reconnects, and it caught this — the fix is
the `start_index` parameter on `encrypt_file()`.

## What is NOT protected (honest limits)
- **Shared passphrase, not per-user accounts.** Anyone with the passphrase can upload,
  download, list and delete any file on that server. This mirrors the Encrypted Chat
  project's trust model, not a multi-tenant system.
- **Filenames and sizes are visible to the server** (needed to store/relay the right
  ciphertext to the right place) even though file *content* is not. `list` reveals
  filenames and sizes to anyone who authenticates.
- **The resume sidecar file** (`<file>.sftresume.json`, kept locally next to the source
  file) holds the file's salt and HMAC in plain text. This is not sensitive on its own
  (useless without the passphrase and the original file), but it is deleted automatically
  once an upload completes.
- **No authentication of *which* client is which** beyond "knows the passphrase" — there is
  no separate identity or access-control layer.
- Not audited. Built with the standard `cryptography` library; no custom cryptographic
  primitives.

## Reporting
Open a GitHub issue (no secrets in it) or contact the author through the GitHub profile.
