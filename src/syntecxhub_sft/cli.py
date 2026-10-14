"""Command-line entry point: `sft upload|download|list|delete ...`."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import List, Optional

from .client import ClientError, FileTransferClient
from .filecrypto import IntegrityError
from .server import get_passphrase
from .transport import TransportError


def _progress(prefix: str):
    def report(done: int, total: int) -> None:
        pct = int(done * 100 / total) if total else 100
        print(f"\r{prefix} {done}/{total} chunks ({pct}%)", end="", flush=True)
        if done >= total:
            print()

    return report


async def _run(args: argparse.Namespace) -> int:
    passphrase = get_passphrase()
    client = FileTransferClient(args.host, args.port, passphrase)
    await client.connect()
    try:
        if args.command == "upload":
            await client.upload(args.file, args.as_name, on_progress=_progress("Uploading"))
            print(f"Uploaded '{args.file}' as '{args.as_name or args.file.split('/')[-1]}'.")
        elif args.command == "download":
            await client.download(args.name, args.out, on_progress=_progress("Downloading"))
            print(f"Downloaded '{args.name}' -> '{args.out}' (integrity verified).")
        elif args.command == "list":
            files = await client.list_files()
            if not files:
                print("(no files stored)")
            for entry in files:
                print(f"{entry['filename']:<40} {entry['size']:>10} bytes")
        elif args.command == "delete":
            await client.delete(args.name)
            print(f"Deleted '{args.name}'.")
    finally:
        await client.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sft", description="Encrypted file transfer client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("upload", help="upload a file")
    up.add_argument("file")
    up.add_argument("--as-name", help="store under a different name than the local file")

    down = sub.add_parser("download", help="download a file")
    down.add_argument("name")
    down.add_argument("out")

    sub.add_parser("list", help="list files on the server")

    delete = sub.add_parser("delete", help="delete a stored file")
    delete.add_argument("name")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except (ClientError, TransportError, IntegrityError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
