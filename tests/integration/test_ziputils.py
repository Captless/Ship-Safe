from scanner.models import FileSnapshot
from scanner.ziputils import iter_text_files, MAX_READ_TEXT


def test_iter_text_files_no_callback(tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 1", encoding="utf-8")
    files = list(iter_text_files(str(tmp_path)))
    assert {f.path for f in files} == {"a.txt", "b.py"}
    for f in files:
        assert isinstance(f, FileSnapshot)
        assert not f.binary


def test_iter_text_files_callback_increments(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("data", encoding="utf-8")
    counts = []
    last = {}

    def progress(fields):
        counts.append(fields["files_discovered"])
        last.update(fields)

    files = list(iter_text_files(str(tmp_path), progress=progress))
    assert counts == [1, 2, 3, 4, 5]
    assert last["files_discovered"] == len(files) == 5


def test_callback_reports_relative_paths(tmp_path):
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "x.py").write_text("x = 1", encoding="utf-8")
    seen = []

    def progress(fields):
        seen.append(fields["current_file"])

    list(iter_text_files(str(tmp_path), progress=progress))
    assert seen == ["src/x.py"]
    assert not any(str(tmp_path) in s for s in seen)


def test_binary_files_yielded_and_counted(tmp_path):
    (tmp_path / "data.bin").write_bytes(b"\x00\xff\xfe")
    (tmp_path / "a.txt").write_text("hi", encoding="utf-8")
    counts = []

    def progress(fields):
        counts.append(fields["files_discovered"])

    files = list(iter_text_files(str(tmp_path), progress=progress))
    assert len(files) == 2
    assert any(f.binary for f in files)
    assert counts[-1] == 2


def test_oversized_file_skipped(tmp_path):
    with open(tmp_path / "big.txt", "wb") as f:
        f.write(b"x" * (MAX_READ_TEXT + 1))
    (tmp_path / "small.txt").write_text("ok", encoding="utf-8")
    counts = []

    def progress(fields):
        counts.append(fields["files_discovered"])

    files = list(iter_text_files(str(tmp_path), progress=progress))
    assert [f.path for f in files] == ["small.txt"]
    assert counts == [1]


def test_invalid_encoding_falls_back(tmp_path):
    (tmp_path / "bad.txt").write_bytes(bytes([0xFF, 0xFE, 0x41]))
    files = list(iter_text_files(str(tmp_path)))
    assert len(files) == 1
    assert not files[0].binary


def test_callback_does_not_alter_snapshots(tmp_path):
    (tmp_path / "a.txt").write_text("content", encoding="utf-8")

    def progress(fields):
        pass

    files = list(iter_text_files(str(tmp_path), progress=progress))
    assert files[0].path == "a.txt"
    assert files[0].content == "content"
    assert not files[0].binary


def test_large_fixture_produces_multiple_updates(tmp_path):
    sub = tmp_path / "pkg"
    sub.mkdir()
    for i in range(60):
        (sub / f"m{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
    counts = []

    def progress(fields):
        counts.append(fields["files_discovered"])

    files = list(iter_text_files(str(tmp_path), progress=progress))
    assert len(files) == 60
    assert counts[-1] == 60
    assert len(set(counts)) == 60
