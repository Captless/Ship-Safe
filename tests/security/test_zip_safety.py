import zipfile
from pathlib import Path

import pytest

from scanner.ziputils import safe_extract_zip, ZipSafetyError


def test_zip_slip_rejected(tmp_path):
    bad = tmp_path / "slip.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("../../escape.txt", "pwn")
    with pytest.raises(ZipSafetyError):
        safe_extract_zip(str(bad))


def test_absolute_path_rejected(tmp_path):
    bad = tmp_path / "abs.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("/etc/passwd", "x")
    with pytest.raises(ZipSafetyError):
        safe_extract_zip(str(bad))


def test_zip_bomb_ratio_rejected(tmp_path):
    bad = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", "A" * (50 * 1024 * 1024))
    with pytest.raises(ZipSafetyError):
        safe_extract_zip(str(bad))


def test_too_many_entries_rejected(tmp_path):
    bad = tmp_path / "many.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        for i in range(6000):
            zf.writestr(f"f{i}.txt", "x")
    with pytest.raises(ZipSafetyError):
        safe_extract_zip(str(bad))


def test_symlink_entry_rejected(tmp_path):
    bad = tmp_path / "link.zip"
    mode = 0o120777 << 16
    info = zipfile.ZipInfo("link")
    info.external_attr = mode
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ZipSafetyError):
        safe_extract_zip(str(bad))


def test_normal_zip_extracts(tmp_path):
    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as zf:
        zf.writestr("src/a.py", "print(1)")
        zf.writestr("b.txt", "hello")
    root = safe_extract_zip(str(good))
    try:
        assert (Path(root) / "src" / "a.py").exists()
        assert (Path(root) / "b.txt").exists()
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)


def test_nested_zip_not_extracted(tmp_path):
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", "PK\x03\x04fake")
    root = safe_extract_zip(str(outer))
    try:
        inner = Path(root) / "inner.zip"
        assert inner.exists()
        assert not (Path(root) / "inner").exists()
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)
