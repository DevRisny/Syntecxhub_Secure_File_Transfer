"""Transport-layer security for the connection itself: an ephemeral X25519 key exchange,
authenticated with a pre-shared passphrase, protecting every byte on the wire (control
messages and file chunks alike) against eavesdropping, tampering and replay.

This is deliberately the same design as the Encrypted Chat project (fresh keys per
connection, HKDF key schedule, HMAC passphrase auth, AES-256-GCM with counter nonces) —
see SECURITY.md for why the file itself gets a *second*, independent layer of encryption
on top of this one.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from contextlib import suppress
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROTOCOL = b"syntecxhub-sft/1"
VERSION = 1
KEY_LEN, NONCE_PREFIX_LEN, COUNTER_LEN, TAG_LEN = 32, 4, 8, 16
SALT_LEN, RANDOM_LEN, PUBKEY_LEN = 16, 16, 32
MAX_COUNTER = 2**64 - 1
CLIENT_HELLO_LEN = 1 + PUBKEY_LEN + RANDOM_LEN
SERVER_HELLO_LEN = 1 + PUBKEY_LEN + RANDOM_LEN + SALT_LEN
MAX_FRAME = 1024 * 1024  # 1 MiB per transport frame (chunk size is kept well under this)
SCRYPT_N = 2**14


class TransportError(Exception):
    """Handshake, framing, or decryption failure on the transport layer."""


class AuthError(TransportError):
    """The peer does not know the passphrase."""


def derive_psk(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise TransportError("passphrase cannot be empty")
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))


def _keypair() -> Tuple[X25519PrivateKey, bytes]:
    private = X25519PrivateKey.generate()
    return private, private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class Session:
    """Encrypts/decrypts frames for one connection, one key+counter per direction."""

    def __init__(self, send_key, recv_key, send_prefix, recv_prefix, send_aad, recv_aad):
        self._send, self._recv = AESGCM(send_key), AESGCM(recv_key)
        self._send_prefix, self._recv_prefix = send_prefix, recv_prefix
        self._send_aad, self._recv_aad = send_aad, recv_aad
        self.send_counter = 0
        self.recv_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.send_counter >= MAX_COUNTER:
            raise TransportError("message limit reached, reconnect")
        counter = self.send_counter.to_bytes(COUNTER_LEN, "big")
        sealed = self._send.encrypt(self._send_prefix + counter, plaintext, self._send_aad)
        self.send_counter += 1
        return counter + sealed

    def decrypt(self, frame: bytes) -> bytes:
        if len(frame) < COUNTER_LEN + TAG_LEN:
            raise TransportError("frame too short")
        counter, sealed = frame[:COUNTER_LEN], frame[COUNTER_LEN:]
        if int.from_bytes(counter, "big") != self.recv_counter:
            raise TransportError("unexpected counter (replayed, dropped or reordered frame)")
        try:
            plaintext = self._recv.decrypt(self._recv_prefix + counter, sealed, self._recv_aad)
        except InvalidTag:
            raise TransportError("frame failed authentication") from None
        self.recv_counter += 1
        return plaintext


def _derive_session(private_key, peer_public, client_hello, server_hello, *, is_client):
    transcript = hashlib.sha256(PROTOCOL + b"\x00" + client_hello + server_hello).digest()
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError:
        raise TransportError("invalid public key") from None
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_LEN + 2 * NONCE_PREFIX_LEN,
        salt=transcript,
        info=PROTOCOL + b" key schedule",
    ).derive(shared)
    k_c2s, k_s2c = okm[:KEY_LEN], okm[KEY_LEN : 2 * KEY_LEN]
    p_c2s = okm[2 * KEY_LEN : 2 * KEY_LEN + NONCE_PREFIX_LEN]
    p_s2c = okm[2 * KEY_LEN + NONCE_PREFIX_LEN :]
    a_c2s, a_s2c = PROTOCOL + b"|c2s|" + transcript, PROTOCOL + b"|s2c|" + transcript
    if is_client:
        return Session(k_c2s, k_s2c, p_c2s, p_s2c, a_c2s, a_s2c), transcript
    return Session(k_s2c, k_c2s, p_s2c, p_c2s, a_s2c, a_c2s), transcript


def _auth_tag(psk: bytes, role: bytes, transcript: bytes) -> bytes:
    return hmac.new(psk, b"auth|" + role + b"|" + transcript, hashlib.sha256).digest()


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    length = int.from_bytes(header, "big")
    if length == 0 or length > MAX_FRAME:
        raise TransportError(f"invalid frame length {length}")
    return await reader.readexactly(length)


def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if not payload or len(payload) > MAX_FRAME:
        raise TransportError("frame size not allowed")
    writer.write(len(payload).to_bytes(4, "big") + payload)


async def server_handshake(reader, writer, psk: bytes, salt: bytes) -> Session:
    client_hello = await _read_frame(reader)
    if len(client_hello) != CLIENT_HELLO_LEN or client_hello[0] != VERSION:
        raise TransportError("bad client hello")
    client_public = client_hello[1 : 1 + PUBKEY_LEN]
    private, public = _keypair()
    server_hello = bytes([VERSION]) + public + secrets.token_bytes(RANDOM_LEN) + salt
    _write_frame(writer, server_hello)
    await writer.drain()
    session, transcript = _derive_session(private, client_public, client_hello, server_hello, is_client=False)
    client_tag = await _read_frame(reader)
    if not hmac.compare_digest(_auth_tag(psk, b"client", transcript), client_tag):
        raise AuthError("client failed passphrase authentication")
    _write_frame(writer, _auth_tag(psk, b"server", transcript))
    await writer.drain()
    return session


async def client_handshake(reader, writer, passphrase: str) -> Session:
    private, public = _keypair()
    client_hello = bytes([VERSION]) + public + secrets.token_bytes(RANDOM_LEN)
    _write_frame(writer, client_hello)
    await writer.drain()
    try:
        server_hello = await _read_frame(reader)
        if len(server_hello) != SERVER_HELLO_LEN or server_hello[0] != VERSION:
            raise TransportError("bad server hello")
        server_public = server_hello[1 : 1 + PUBKEY_LEN]
        salt = server_hello[1 + PUBKEY_LEN + RANDOM_LEN :]
        psk = derive_psk(passphrase, salt)
        session, transcript = _derive_session(
            private, server_public, client_hello, server_hello, is_client=True
        )
        _write_frame(writer, _auth_tag(psk, b"client", transcript))
        await writer.drain()
        server_tag = await _read_frame(reader)
    except (asyncio.IncompleteReadError, ConnectionError):
        raise AuthError("handshake failed: wrong passphrase or not an SFT server") from None
    if not hmac.compare_digest(_auth_tag(psk, b"server", transcript), server_tag):
        raise AuthError("server failed passphrase authentication")
    return session


class SecureTransport:
    """Send/receive opaque encrypted frames after a successful handshake."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session: Session):
        self._reader, self._writer, self._session = reader, writer, session

    async def send(self, payload: bytes) -> None:
        _write_frame(self._writer, self._session.encrypt(payload))
        await self._writer.drain()

    async def recv(self) -> bytes:
        return self._session.decrypt(await _read_frame(self._reader))

    def close(self) -> None:
        with suppress(Exception):
            self._writer.close()

    async def wait_closed(self) -> None:
        with suppress(Exception):
            await self._writer.wait_closed()
