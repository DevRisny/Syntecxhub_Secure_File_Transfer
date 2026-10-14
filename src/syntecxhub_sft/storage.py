"""Server-side storage: every byte written to disk is exactly the ciphertext the server
received — it is never decrypted here, so a compromise of the server's disk alone does not
expose file contents (see SECURITY.md). Resume works by counting which chunk files already
exist for an in-progress upload.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Iterator, Tuple

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,119}$")


class StorageError(Exception):
    pass


def safe_name(name: str) -> str:
    """Reject path traversal / unusual characters; a stored filename is never a path."""
    if not name or not SAFE_NAME_RE.match(name) or ".." in name:
        raise StorageError(f"unsafe or invalid filename: {name!r}")
    return name


class Storage:
    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _dir(self, filename: str) -> Path:
        return self.root / safe_name(filename)

    def _chunks_dir(self, filename: str) -> Path:
        return self._dir(filename) / "chunks"

    def _manifest_path(self, filename: str, partial: bool) -> Path:
        name = "manifest.json.partial" if partial else "manifest.json"
        return self._dir(filename) / name

    # ---------------------------------------------------------------- upload (write side)
    def begin_upload(self, manifest: dict) -> int:
        """Create (or resume) an upload. Returns the next expected chunk index."""
        filename = manifest["filename"]
        upload_dir = self._dir(filename)
        chunks_dir = self._chunks_dir(filename)
        partial_path = self._manifest_path(filename, partial=True)
        final_path = self._manifest_path(filename, partial=False)

        if final_path.exists():
            raise StorageError(f"'{filename}' already exists; delete it before re-uploading")

        if partial_path.exists():
            existing = json.loads(partial_path.read_text())
            if existing.get("salt") != manifest.get("salt") or existing.get("hmac") != manifest.get("hmac"):
                raise StorageError(
                    f"an incomplete upload of '{filename}' exists but does not match this "
                    f"file; delete the partial upload on the server before retrying"
                )
            return self.next_expected_index(filename)

        upload_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(upload_dir, 0o700)
        chunks_dir.mkdir(exist_ok=True)
        os.chmod(chunks_dir, 0o700)
        to_write = dict(manifest)
        to_write["uploaded_at"] = time.time()
        partial_path.write_text(json.dumps(to_write))
        os.chmod(partial_path, 0o600)
        return 0

    def next_expected_index(self, filename: str) -> int:
        chunks_dir = self._chunks_dir(filename)
        if not chunks_dir.exists():
            return 0
        index = 0
        while (chunks_dir / f"{index:08d}.bin").exists():
            index += 1
        return index

    def store_chunk(self, filename: str, index: int, ciphertext: bytes) -> None:
        path = self._chunks_dir(filename) / f"{index:08d}.bin"
        if path.exists():
            return  # resume: this chunk was already written, treat as success (idempotent)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(ciphertext)
        os.chmod(tmp, 0o600)
        tmp.replace(path)

    def finalize_upload(self, filename: str, expected_chunk_count: int) -> None:
        got = self.next_expected_index(filename)
        if got != expected_chunk_count:
            raise StorageError(f"expected {expected_chunk_count} chunks but only {got} are stored")
        partial_path = self._manifest_path(filename, partial=True)
        final_path = self._manifest_path(filename, partial=False)
        partial_path.replace(final_path)
        os.chmod(final_path, 0o600)

    # ---------------------------------------------------------------- download (read side)
    def get_manifest(self, filename: str) -> dict:
        path = self._manifest_path(filename, partial=False)
        if not path.exists():
            raise StorageError(f"'{filename}' was not found (or is still uploading)")
        return json.loads(path.read_text())

    def iter_chunks(self, filename: str, chunk_count: int) -> Iterator[Tuple[int, bytes]]:
        chunks_dir = self._chunks_dir(filename)
        for index in range(chunk_count):
            path = chunks_dir / f"{index:08d}.bin"
            if not path.exists():
                raise StorageError(f"chunk {index} of '{filename}' is missing on the server")
            yield index, path.read_bytes()

    def list_files(self) -> list:
        out = []
        for child in sorted(self.root.iterdir()):
            manifest_path = child / "manifest.json"
            if manifest_path.exists():
                data = json.loads(manifest_path.read_text())
                out.append(
                    {
                        "filename": data["filename"],
                        "size": data["size"],
                        "uploaded_at": data.get("uploaded_at"),
                    }
                )
        return out

    def delete(self, filename: str) -> None:
        import shutil

        path = self._dir(filename)
        if not path.exists():
            raise StorageError(f"'{filename}' was not found")
        shutil.rmtree(path)
