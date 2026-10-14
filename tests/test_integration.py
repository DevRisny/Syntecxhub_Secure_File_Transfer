"""End-to-end tests: a real asyncio server and real client, talking over real sockets."""

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from syntecxhub_sft import protocol
from syntecxhub_sft.client import RESUME_SUFFIX, ClientError, FileTransferClient
from syntecxhub_sft.filecrypto import IntegrityError, derive_file_keys
from syntecxhub_sft.server import FileTransferServer
from syntecxhub_sft.storage import Storage
from syntecxhub_sft.transport import AuthError

PASS = "correct horse battery staple"


class Tap:
    """A TCP proxy that records every byte exchanged (what a network sniffer would see)."""

    def __init__(self, target_port):
        self.target_port = target_port
        self.seen = bytearray()
        self.port = 0
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        self._server.close()

    async def _handle(self, reader, writer):
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.target_port)

        async def pipe(src, dst):
            try:
                while True:
                    header = await src.readexactly(4)
                    body = await src.readexactly(int.from_bytes(header, "big"))
                    self.seen += header + body
                    dst.write(header + body)
                    await dst.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))


class SftTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.storage_dir = tempfile.TemporaryDirectory()
        self.work_dir = tempfile.TemporaryDirectory()
        self.server = FileTransferServer(PASS, Storage(self.storage_dir.name), port=0)
        await self.server.start()
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            await client.close()
        await self.server.stop()
        self.storage_dir.cleanup()
        self.work_dir.cleanup()

    async def new_client(self, passphrase=PASS, port=None) -> FileTransferClient:
        client = FileTransferClient("127.0.0.1", port or self.server.port, passphrase)
        await client.connect()
        self.clients.append(client)
        return client

    def make_file(self, name: str, data: bytes) -> str:
        path = Path(self.work_dir.name) / name
        path.write_bytes(data)
        return str(path)


class UploadDownloadTests(SftTestCase):
    async def test_small_file_round_trip(self):
        client = await self.new_client()
        src = self.make_file("note.txt", b"hello secure world")
        await client.upload(src)
        out = str(Path(self.work_dir.name) / "note_out.txt")
        await client.download("note.txt", out)
        self.assertEqual(Path(out).read_bytes(), b"hello secure world")

    async def test_multi_chunk_file_round_trip(self):
        client = await self.new_client()
        data = os.urandom(50_000)
        src = self.make_file("blob.bin", data)
        await client.upload(src, chunk_size=1000)
        out = str(Path(self.work_dir.name) / "blob_out.bin")
        await client.download("blob.bin", out)
        self.assertEqual(Path(out).read_bytes(), data)

    async def test_empty_file(self):
        client = await self.new_client()
        src = self.make_file("empty.txt", b"")
        await client.upload(src)
        out = str(Path(self.work_dir.name) / "empty_out.txt")
        await client.download("empty.txt", out)
        self.assertEqual(Path(out).read_bytes(), b"")

    async def test_text_and_binary_content_survive_exactly(self):
        client = await self.new_client()
        data = bytes(range(256)) * 10  # every byte value, including nulls and newlines
        src = self.make_file("binary.dat", data)
        await client.upload(src, chunk_size=37)  # deliberately odd chunk size
        out = str(Path(self.work_dir.name) / "binary_out.dat")
        await client.download("binary.dat", out)
        self.assertEqual(Path(out).read_bytes(), data)

    async def test_list_and_delete(self):
        client = await self.new_client()
        await client.upload(self.make_file("a.txt", b"aaa"))
        await client.upload(self.make_file("b.txt", b"bbb"))
        files = {f["filename"] for f in await client.list_files()}
        self.assertEqual(files, {"a.txt", "b.txt"})
        await client.delete("a.txt")
        files = {f["filename"] for f in await client.list_files()}
        self.assertEqual(files, {"b.txt"})

    async def test_downloading_missing_file_raises(self):
        client = await self.new_client()
        with self.assertRaises(ClientError):
            await client.download("nope.txt", str(Path(self.work_dir.name) / "x"))

    async def test_cannot_overwrite_existing_upload(self):
        client = await self.new_client()
        src = self.make_file("dup.txt", b"first")
        await client.upload(src)
        with self.assertRaises(ClientError):
            await client.upload(src)


class AuthTests(SftTestCase):
    async def test_wrong_passphrase_rejected(self):
        with self.assertRaises((ClientError, AuthError)):
            await self.new_client(passphrase="totally wrong passphrase")

    async def test_cross_passphrase_cannot_decrypt(self):
        """Different transport passphrase can't even connect, so a stolen on-disk file alone
        (without the passphrase) is useless, which is the point of the file-level key."""
        salt = os.urandom(16)
        right = derive_file_keys(PASS, salt)
        wrong = derive_file_keys("not the passphrase", salt)
        self.assertNotEqual(right.aes_key, wrong.aes_key)


class ResumeTests(SftTestCase):
    async def test_interrupted_upload_resumes_and_matches_original(self):
        data = os.urandom(20_000)
        src = self.make_file("resume.bin", data)
        chunk_size = 1000

        # First attempt: send only the first few chunks, then disconnect without finishing.
        first = FileTransferClient("127.0.0.1", self.server.port, PASS)
        await first.connect()
        import base64
        import json

        from syntecxhub_sft.filecrypto import derive_file_keys as dfk
        from syntecxhub_sft.filecrypto import encrypt_file, new_salt, whole_file_hmac

        salt = new_salt()
        keys = dfk(PASS, salt)
        with open(src, "rb") as fh:
            file_hmac = whole_file_hmac(fh, keys, chunk_size)
        size = len(data)
        chunk_count = (size + chunk_size - 1) // chunk_size
        state = {
            "filename": "resume.bin",
            "size": size,
            "mtime": Path(src).stat().st_mtime,
            "chunk_size": chunk_size,
            "salt": base64.b64encode(salt).decode(),
            "hmac": base64.b64encode(file_hmac).decode(),
        }
        Path(src + RESUME_SUFFIX).write_text(json.dumps(state))

        await first._send_json(
            {
                "type": "upload_begin",
                "filename": "resume.bin",
                "size": size,
                "chunk_size": chunk_size,
                "chunk_count": chunk_count,
                "salt": state["salt"],
                "hmac": state["hmac"],
            }
        )
        await first._recv_json("resume_info")
        with open(src, "rb") as fh:
            sent = 0
            for index, ciphertext in encrypt_file(fh, keys, chunk_size):
                if sent >= 3:
                    break
                await first._transport.send(protocol.encode_chunk(index, ciphertext))
                sent += 1
        first._transport.close()  # simulate a dropped connection: no upload_end was sent
        await asyncio.sleep(0.1)

        # Second attempt: a fresh client, same source file (same resume sidecar) -> must resume.
        second = await self.new_client()
        await second.upload(src, chunk_size=chunk_size)
        self.assertFalse(Path(src + RESUME_SUFFIX).exists())  # cleaned up on success

        out = str(Path(self.work_dir.name) / "resume_out.bin")
        await second.download("resume.bin", out)
        self.assertEqual(Path(out).read_bytes(), data)

    async def test_changed_file_does_not_reuse_stale_resume_state(self):
        src = self.make_file("changing.txt", b"version one")
        resume_path = Path(src + RESUME_SUFFIX)
        resume_path.write_text('{"size": 999, "mtime": 1.0, "chunk_size": 1000, "salt": "x", "hmac": "y"}')
        client = await self.new_client()
        await client.upload(src)  # stale sidecar must be ignored, not crash
        out = str(Path(self.work_dir.name) / "changing_out.txt")
        await client.download("changing.txt", out)
        self.assertEqual(Path(out).read_bytes(), b"version one")


class IntegrityTests(SftTestCase):
    async def test_tampered_stored_chunk_is_detected_on_download(self):
        client = await self.new_client()
        src = self.make_file("important.txt", b"wire the funds to account 42")
        await client.upload(src)

        chunk_path = Path(self.storage_dir.name) / "important.txt" / "chunks" / "00000000.bin"
        data = bytearray(chunk_path.read_bytes())
        data[-1] ^= 1
        chunk_path.write_bytes(bytes(data))

        out = str(Path(self.work_dir.name) / "important_out.txt")
        with self.assertRaises(IntegrityError):
            await client.download("important.txt", out)
        self.assertFalse(Path(out).exists())  # corrupted output must not be left behind


class WireSecurityTests(SftTestCase):
    async def test_no_plaintext_filename_content_or_passphrase_on_the_wire(self):
        tap = Tap(self.server.port)
        await tap.start()
        try:
            client = await self.new_client(port=tap.port)
            src = self.make_file("payroll.csv", b"alice,90000\nbob,85000\nSUPER-SECRET-NOTE")
            await client.upload(src, remote_name="payroll.csv")
            out = str(Path(self.work_dir.name) / "payroll_out.csv")
            await client.download("payroll.csv", out)
        finally:
            await tap.stop()
        blob = bytes(tap.seen)
        self.assertGreater(len(blob), 200)
        for needle in (b"payroll.csv", b"alice", b"90000", b"SUPER-SECRET-NOTE", PASS.encode()):
            self.assertNotIn(needle, blob)


if __name__ == "__main__":
    unittest.main()
