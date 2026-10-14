"""Asyncio server: authenticates a connection, then serves upload/download/list/delete
requests. The server stores and relays ciphertext only — see filecrypto.py and storage.py."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import secrets
import sys
from typing import List, Optional

from . import protocol
from .storage import Storage, StorageError, safe_name
from .transport import AuthError, SecureTransport, TransportError, derive_psk, server_handshake

ENV_PASSPHRASE = "SYNTECXHUB_SFT_PASSPHRASE"
HANDSHAKE_TIMEOUT = 10.0
IDLE_TIMEOUT = 5 * 60
MAX_CHUNK_CIPHERTEXT = 4 * 1024 * 1024  # generous cap per chunk message (well above default chunk size)

log = logging.getLogger("syntecxhub.sft.server")


class FileTransferServer:
    def __init__(self, passphrase: str, storage: Storage, host: str = "127.0.0.1", port: int = 6000) -> None:
        self.host, self.port = host, port
        self.storage = storage
        self._salt = secrets.token_bytes(16)
        self._psk = derive_psk(passphrase, self._salt)
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("listening on %s:%d, storage at %s", self.host, self.port, self.storage.root)

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        transport = None
        try:
            session = await asyncio.wait_for(
                server_handshake(reader, writer, self._psk, self._salt), HANDSHAKE_TIMEOUT
            )
            transport = SecureTransport(reader, writer, session)
            log.info("%s authenticated", peer)
            await self._session_loop(transport)
        except asyncio.TimeoutError:
            log.warning("timeout from %s", peer)
        except AuthError as exc:
            log.warning("rejected %s: %s", peer, exc)
        except (TransportError, protocol.ProtocolError) as exc:
            log.warning("protocol error from %s: %s", peer, exc)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception:
            log.exception("unexpected error with %s", peer)
        finally:
            if transport is not None:
                transport.close()
            else:
                writer.close()

    async def _session_loop(self, transport: SecureTransport) -> None:
        current_upload: Optional[dict] = None  # {"filename": str, "chunk_count": int}
        while True:
            payload = await asyncio.wait_for(transport.recv(), IDLE_TIMEOUT)
            kind, message = protocol.decode(payload)

            if kind == "chunk":
                index, ciphertext = message
                if current_upload is None:
                    await self._error(transport, "no upload in progress")
                    continue
                if len(ciphertext) > MAX_CHUNK_CIPHERTEXT:
                    await self._error(transport, "chunk too large")
                    continue
                self.storage.store_chunk(current_upload["filename"], index, ciphertext)
                continue

            msg_type = message.get("type")
            try:
                if msg_type == "upload_begin":
                    filename = safe_name(message["filename"])
                    manifest = {k: v for k, v in message.items() if k != "type"}
                    manifest["filename"] = filename
                    next_index = self.storage.begin_upload(manifest)
                    current_upload = {"filename": filename, "chunk_count": message["chunk_count"]}
                    await transport.send(
                        protocol.encode_json({"type": "resume_info", "next_chunk": next_index})
                    )
                elif msg_type == "upload_end":
                    if current_upload is None:
                        raise StorageError("no upload in progress")
                    self.storage.finalize_upload(current_upload["filename"], current_upload["chunk_count"])
                    log.info(
                        "stored '%s' (%d chunks)", current_upload["filename"], current_upload["chunk_count"]
                    )
                    await transport.send(protocol.encode_json({"type": "ack", "status": "ok"}))
                    current_upload = None
                elif msg_type == "download_request":
                    await self._handle_download(transport, safe_name(message["filename"]))
                elif msg_type == "list_request":
                    await transport.send(
                        protocol.encode_json({"type": "file_list", "files": self.storage.list_files()})
                    )
                elif msg_type == "delete_request":
                    self.storage.delete(safe_name(message["filename"]))
                    await transport.send(protocol.encode_json({"type": "ack", "status": "ok"}))
                elif msg_type == "quit":
                    return
                else:
                    await self._error(transport, f"unknown message type '{msg_type}'")
            except StorageError as exc:
                await self._error(transport, str(exc))

    async def _handle_download(self, transport: SecureTransport, filename: str) -> None:
        manifest = self.storage.get_manifest(filename)
        await transport.send(protocol.encode_json({"type": "manifest", **manifest}))
        for index, ciphertext in self.storage.iter_chunks(filename, manifest["chunk_count"]):
            await transport.send(protocol.encode_chunk(index, ciphertext))
        await transport.send(protocol.encode_json({"type": "download_end"}))
        log.info("sent '%s' (%d chunks)", filename, manifest["chunk_count"])

    @staticmethod
    async def _error(transport: SecureTransport, message: str) -> None:
        await transport.send(protocol.encode_json({"type": "error", "message": message}))


def get_passphrase(confirm: bool = False) -> str:
    value = os.environ.get(ENV_PASSPHRASE)
    if value:
        return value
    value = getpass.getpass("Transfer passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != value:
        raise SystemExit("passphrases do not match")
    return value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sft-server", description="Encrypted file transfer server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--storage", default="sft_storage", help="directory to store encrypted files in")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    passphrase = get_passphrase(confirm=True)
    if len(passphrase) < 8:
        print("passphrase must have at least 8 characters", file=sys.stderr)
        return 2

    server = FileTransferServer(passphrase, Storage(args.storage), args.host, args.port)

    async def run() -> None:
        await server.start()
        print(f"Encrypted file transfer server on {args.host}:{server.port}  (Ctrl+C to stop)")
        await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as exc:
        print(f"cannot start server: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
