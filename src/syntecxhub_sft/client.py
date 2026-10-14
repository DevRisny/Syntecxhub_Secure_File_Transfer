"""Client: upload, download, list and delete, plus the resume bookkeeping."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Callable, List, Optional

from . import protocol
from .filecrypto import (
    IntegrityError,
    decrypt_chunk,
    derive_file_keys,
    encrypt_file,
    new_salt,
    whole_file_hmac,
)
from .storage import safe_name
from .transport import AuthError, SecureTransport, TransportError, client_handshake

DEFAULT_CHUNK_SIZE = 256 * 1024
RESUME_SUFFIX = ".sftresume.json"
ProgressFn = Optional[Callable[[int, int], None]]  # (chunks_done, chunk_count)


class ClientError(Exception):
    """A clean, user-facing error (bad passphrase, server error, integrity failure, ...)."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class FileTransferClient:
    def __init__(self, host: str, port: int, passphrase: str) -> None:
        self.host, self.port, self._passphrase = host, port, passphrase
        self._transport: Optional[SecureTransport] = None

    async def connect(self, timeout: float = 10.0) -> None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise ClientError(f"cannot connect to {self.host}:{self.port} ({exc})") from None
        try:
            session = await asyncio.wait_for(client_handshake(reader, writer, self._passphrase), timeout)
        except AuthError as exc:
            writer.close()
            raise ClientError(str(exc)) from None
        self._transport = SecureTransport(reader, writer, session)

    async def close(self) -> None:
        if self._transport is None:
            return
        try:
            await self._transport.send(protocol.encode_json({"type": "quit"}))
        except Exception:
            pass
        self._transport.close()
        await self._transport.wait_closed()
        self._transport = None

    async def _send_json(self, message: dict) -> None:
        assert self._transport is not None
        await self._transport.send(protocol.encode_json(message))

    async def _recv(self):
        assert self._transport is not None
        return protocol.decode(await self._transport.recv())

    async def _recv_json(self, expect_type: Optional[str] = None) -> dict:
        kind, message = await self._recv()
        if kind != "json":
            raise ClientError("expected a control message but got a chunk")
        if message.get("type") == "error":
            raise ClientError(message.get("message", "server error"))
        if expect_type and message.get("type") != expect_type:
            raise ClientError(f"unexpected reply '{message.get('type')}' (wanted '{expect_type}')")
        return message

    # --------------------------------------------------------------------- upload
    async def upload(
        self,
        local_path: str,
        remote_name: Optional[str] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        on_progress: ProgressFn = None,
    ) -> None:
        path = Path(local_path)
        if not path.is_file():
            raise ClientError(f"no such file: {local_path}")
        remote_name = safe_name(remote_name or path.name)
        size = path.stat().st_size
        resume_path = path.with_name(path.name + RESUME_SUFFIX)

        state = self._load_resume_state(resume_path, path, size, chunk_size)
        if state is None:
            salt = new_salt()
            with open(path, "rb") as fh:
                file_hmac = whole_file_hmac(fh, derive_file_keys(self._passphrase, salt), chunk_size)
            state = {
                "filename": remote_name,
                "size": size,
                "mtime": path.stat().st_mtime,
                "chunk_size": chunk_size,
                "salt": _b64(salt),
                "hmac": _b64(file_hmac),
            }
            resume_path.write_text(json.dumps(state))

        keys = derive_file_keys(self._passphrase, _unb64(state["salt"]))
        chunk_count = (size + chunk_size - 1) // chunk_size if size else 0

        await self._send_json(
            {
                "type": "upload_begin",
                "filename": remote_name,
                "size": size,
                "chunk_size": chunk_size,
                "chunk_count": chunk_count,
                "salt": state["salt"],
                "hmac": state["hmac"],
            }
        )
        reply = await self._recv_json("resume_info")
        start_index = reply["next_chunk"]

        with open(path, "rb") as fh:
            fh.seek(start_index * chunk_size)
            for index, ciphertext in encrypt_file(fh, keys, chunk_size, start_index=start_index):
                await self._transport.send(protocol.encode_chunk(index, ciphertext))
                if on_progress:
                    on_progress(index + 1, chunk_count)

        await self._send_json({"type": "upload_end"})
        await self._recv_json("ack")
        resume_path.unlink(missing_ok=True)

    @staticmethod
    def _load_resume_state(resume_path: Path, source: Path, size: int, chunk_size: int) -> Optional[dict]:
        if not resume_path.exists():
            return None
        try:
            state = json.loads(resume_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        if (
            state.get("size") != size
            or state.get("mtime") != source.stat().st_mtime
            or state.get("chunk_size") != chunk_size
        ):
            return None  # source file changed since the interrupted upload; start fresh
        return state

    # --------------------------------------------------------------------- download
    async def download(self, remote_name: str, dest_path: str, on_progress: ProgressFn = None) -> None:
        await self._send_json({"type": "download_request", "filename": safe_name(remote_name)})
        manifest = await self._recv_json("manifest")
        keys = derive_file_keys(self._passphrase, _unb64(manifest["salt"]))
        chunk_count = manifest["chunk_count"]
        expected_hmac = _unb64(manifest["hmac"])

        tmp_path = Path(dest_path).with_suffix(Path(dest_path).suffix + ".part")
        received = 0
        try:
            with open(tmp_path, "wb") as out:
                while received < chunk_count:
                    kind, message = await self._recv()
                    if kind == "json":
                        raise ClientError(message.get("message", f"unexpected message {message}"))
                    index, ciphertext = message
                    if index != received:
                        raise ClientError(f"received chunk {index} but expected {received} (out of order)")
                    out.write(decrypt_chunk(keys, index, ciphertext))
                    received += 1
                    if on_progress:
                        on_progress(received, chunk_count)
            await self._recv_json("download_end")

            from .filecrypto import check_file_hmac

            if not check_file_hmac(expected_hmac, keys, tmp_path):
                raise IntegrityError(
                    "whole-file integrity check failed: the reassembled file does not match "
                    "the sender's HMAC (corrupted transfer or wrong passphrase)"
                )
        except (IntegrityError, ClientError, TransportError):
            tmp_path.unlink(missing_ok=True)
            raise
        tmp_path.replace(dest_path)

    # --------------------------------------------------------------------- misc
    async def list_files(self) -> List[dict]:
        await self._send_json({"type": "list_request"})
        return (await self._recv_json("file_list"))["files"]

    async def delete(self, remote_name: str) -> None:
        await self._send_json({"type": "delete_request", "filename": safe_name(remote_name)})
        await self._recv_json("ack")
