"""Messages exchanged over the SecureTransport channel: small JSON control messages, and
a compact binary framing for the (much more frequent) file-chunk messages.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

JSON_TAG = b"J"
CHUNK_TAG = b"C"
CHUNK_HEADER_LEN = 1 + 4  # tag byte + 4-byte big-endian chunk index


class ProtocolError(Exception):
    pass


def encode_json(message: Dict[str, Any]) -> bytes:
    return JSON_TAG + json.dumps(message, separators=(",", ":")).encode("utf-8")


def encode_chunk(index: int, ciphertext: bytes) -> bytes:
    if index < 0 or index > 0xFFFFFFFF:
        raise ProtocolError("chunk index out of range")
    return CHUNK_TAG + index.to_bytes(4, "big") + ciphertext


def decode(payload: bytes) -> Tuple[str, Any]:
    """Returns ("json", dict) or ("chunk", (index, ciphertext))."""
    if not payload:
        raise ProtocolError("empty message")
    tag, body = payload[:1], payload[1:]
    if tag == JSON_TAG:
        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProtocolError("invalid JSON control message") from None
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            raise ProtocolError("control message must be a JSON object with a 'type'")
        return "json", obj
    if tag == CHUNK_TAG:
        if len(body) < 4:
            raise ProtocolError("chunk message too short")
        index = int.from_bytes(body[:4], "big")
        return "chunk", (index, body[4:])
    raise ProtocolError(f"unknown message tag {tag!r}")
