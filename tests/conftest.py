import zipfile
from pathlib import Path

import pytest

from scanner.models import FileSnapshot

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture_tree(root: Path):
    out = []
    for p in root.rglob("*"):
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = ""
            out.append(FileSnapshot(path=p.relative_to(root).as_posix(), content=content))
    return out


def make_zip(root: Path, dst: Path) -> Path:
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in root.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(root).as_posix())
    return dst


@pytest.fixture
def vuln_project():
    root = FIXTURES / "vuln"
    return read_fixture_tree(root)


@pytest.fixture
def clean_project():
    root = FIXTURES / "clean"
    return read_fixture_tree(root)


@pytest.fixture
def vuln_zip(tmp_path):
    dst = tmp_path / "vuln.zip"
    return make_zip(FIXTURES / "vuln", dst)


@pytest.fixture
def clean_zip(tmp_path):
    dst = tmp_path / "clean.zip"
    return make_zip(FIXTURES / "clean", dst)
