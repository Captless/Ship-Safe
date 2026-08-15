from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import PurePosixPath

from scanner.models import FileSnapshot

MAX_ENTRIES = 5000
MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024
MAX_PER_FILE = 10 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_READ_TEXT = 2 * 1024 * 1024


class ZipSafetyError(Exception):
    pass


def _safe_join(root: str, entry: str) -> str:
    path = PurePosixPath(entry)
    if path.is_absolute() or ".." in path.parts:
        raise ZipSafetyError(f"unsafe path: {entry}")
    resolved = os.path.realpath(os.path.join(root, *path.parts))
    root_real = os.path.realpath(root)
    if not resolved.startswith(root_real + os.sep) and resolved != root_real:
        raise ZipSafetyError(f"path escapes root: {entry}")
    return resolved


def safe_extract_zip(zip_path: str) -> str:
    workdir = tempfile.mkdtemp(prefix="shipsafe_")
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ZipSafetyError("too many entries")
            total = 0
            for info in infos:
                total += info.file_size
                if total > MAX_TOTAL_UNCOMPRESSED:
                    raise ZipSafetyError("archive too large uncompressed")
                if info.file_size > MAX_PER_FILE:
                    raise ZipSafetyError("single file too large")
                if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    raise ZipSafetyError("suspicious compression ratio")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ZipSafetyError(f"symlink entry: {info.filename}")
                target = _safe_join(workdir, info.filename)
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 256)
                        if not chunk:
                            break
                        dst.write(chunk)
        return workdir
    except Exception:
        import shutil

        shutil.rmtree(workdir, ignore_errors=True)
        raise


def iter_text_files(root: str, max_files: int = 4000):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.getsize(full) > MAX_READ_TEXT:
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="strict") as f:
                    yield FileSnapshot(path=rel, content=f.read())
            except (UnicodeDecodeError, OSError):
                try:
                    with open(full, "rb") as f:
                        head = f.read(4096)
                except OSError:
                    continue
                if b"\x00" in head:
                    yield FileSnapshot(path=rel, content="", binary=True)
                    continue
                try:
                    with open(full, "r", encoding="latin-1") as f:
                        yield FileSnapshot(path=rel, content=f.read())
                except OSError:
                    continue


def cleanup_workspace(root: str) -> None:
    import shutil

    shutil.rmtree(root, ignore_errors=True)
