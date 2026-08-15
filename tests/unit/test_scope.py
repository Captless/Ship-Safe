from scanner.scope import is_ignored, should_analyze, normalize_path


def test_excluded_dirs():
    for p in [
        "node_modules/foo/bar.js",
        "vendor/lib.py",
        ".git/hooks/pre-commit",
        ".svn/entries",
        ".hg/store",
        "dist/bundle.js",
        "build/app.js",
        "out/index.html",
        ".next/server.js",
        ".nuxt/app.js",
        ".cache/x.js",
        "coverage/lcov.py",
        "tmp/x.js",
        "temp/x.js",
        "target/x.py",
        "__pycache__/mod.pyc",
        ".pytest_cache/x",
    ]:
        assert is_ignored(p), p


def test_excluded_artifacts():
    assert is_ignored("src/app.min.js")
    assert is_ignored("src/styles.min.css")
    assert is_ignored("src/bundle.js.map")
    assert is_ignored("dist/chunk.min.js.map")


def test_app_source_analyzed():
    for p in [
        "src/app.js",
        "app/page.tsx",
        "components/Button.tsx",
        "server/api.py",
        "routes.py",
        "lib/utils.py",
        "services/auth.js",
        "api/users.ts",
        "package.json",
        "requirements.txt",
    ]:
        assert should_analyze(p), p


def test_nested_node_modules_ignored():
    assert is_ignored("src/node_modules/deep/lib.js")
    assert is_ignored("frontend/node_modules/react/index.js")


def test_windows_paths():
    assert is_ignored("node_modules\\foo\\bar.js")
    assert is_ignored("dist\\bundle.js")
    assert is_ignored(".git\\hooks\\pre-commit")
    assert should_analyze("src\\app.js")
    assert should_analyze("backend\\main.py")


def test_normalize():
    assert normalize_path("a\\b/c") == "a/b/c"
    assert normalize_path("./a") == "a"
    assert normalize_path("../a") == "../a"
