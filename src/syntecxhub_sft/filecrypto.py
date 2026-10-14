"""File-level encryption: a second, independent layer on top of the transport security.

Why a second layer? The transport session key is ephemeral and known to the server (the
server is one endpoint of that connection). If files were only protected by the transport
layer, the server would see plaintext file content. Instead, the file is encrypted with a
key derived straight from the shared passphrase and a random per-file salt — the server
only ever stores and relays ciphertext, and never computes or sees this key. See
SECURITY.md for the full threat model.

Design
  * File key + HMAC key: scrypt(passphrase, file_salt) -> HKDF -> two independent keys
    (one for AES-256-GCM, one for the whole-file HMAC-SHA256).
  * Per-chunk encryption: AES-256-GCM, nonce = 12-byte big-endian chunk index (unique per
    key because a fresh salt -> fresh key is used for every file).
  * Whole-file integrity: HMAC-SHA256 computed over the *plaintext* while chunking, and
    checked again by the receiver after every chunk has been decrypted and reassembled —
    this catches a dropped, duplicated or reordered chunk even though each chunk's own
    GCM tag already caught per-chunk tampering.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FILE_SALT_LEN = 16
KEY_LEN = 32
TAG_LEN = 16
DEFAULT_CHUNK_SIZE = 256 * 1024  # 256 KiB plaintext per chunk
SCRYPT_N = 2**14


class IntegrityError(Exception):
    """A chunk's authentication tag, or the whole file's HMAC, did not match."""


@dataclass
class FileKeys:
    aes_key: bytes
    hmac_key: bytes


def derive_file_keys(passphrase: str, salt: bytes) -> FileKeys:
    if not passphrase:
        raise ValueError("passphrase cannot be empty")
    root = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))
    okm = HKDF(
        algorithm=hashes.SHA256(), length=2 * KEY_LEN, salt=salt, info=b"syntecxhub-sft-file-keys"
    ).derive(root)
    return FileKeys(aes_key=okm[:KEY_LEN], hmac_key=okm[KEY_LEN:])


def _nonce(index: int) -> bytes:
    return index.to_bytes(12, "big")


def encrypt_file(
    source: BinaryIO, keys: FileKeys, chunk_size: int = DEFAULT_CHUNK_SIZE, start_index: int = 0
) -> Iterator[Tuple[int, bytes]]:
    """Yield (chunk_index, ciphertext) for the whole file, streaming (does not load it all
    into memory). The caller should also call whole_file_hmac() to get the value to send
    in the manifest — call it on the same stream before/independent of this.

    `start_index` matters for resume: the nonce is derived from the chunk index, so when
    resuming a transfer at file offset `start_index * chunk_size`, the caller MUST also
    pass `start_index` here (not leave it at 0), or the nonce for the resumed chunks would
    collide with the nonce already used for the earlier chunks at those same indices —
    exactly the nonce reuse AES-GCM depends on never happening.
    """
    aesgcm = AESGCM(keys.aes_key)
    index = start_index
    while True:
        plaintext = source.read(chunk_size)
        if not plaintext:
            break
        ciphertext = aesgcm.encrypt(_nonce(index), plaintext, None)
        yield index, ciphertext
        index += 1


def decrypt_chunk(keys: FileKeys, index: int, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(keys.aes_key)
    try:
        return aesgcm.decrypt(_nonce(index), ciphertext, None)
    except InvalidTag:
        raise IntegrityError(f"chunk {index} failed authentication (tampered or wrong key)") from None


def whole_file_hmac(source: BinaryIO, keys: FileKeys, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """Stream the file once to compute an HMAC-SHA256 over its plaintext bytes."""
    mac = hmac.new(keys.hmac_key, digestmod=hashlib.sha256)
    while True:
        block = source.read(chunk_size)
        if not block:
            break
        mac.update(block)
    return mac.digest()


def check_file_hmac(expected: bytes, keys: FileKeys, path) -> bool:
    mac = hmac.new(keys.hmac_key, digestmod=hashlib.sha256)
    with open(path, "rb") as fh:
        while True:
            block = fh.read(DEFAULT_CHUNK_SIZE)
            if not block:
                break
            mac.update(block)
    return hmac.compare_digest(mac.digest(), expected)


def new_salt() -> bytes:
    return secrets.token_bytes(FILE_SALT_LEN)
