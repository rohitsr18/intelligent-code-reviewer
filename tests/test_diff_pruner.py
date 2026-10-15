import pytest
from fastapi.testclient import TestClient
from app.reviewer.diff_pruner import DiffPruner, PrunedDiffResult
from app.main import app


@pytest.fixture
def pruner():
    return DiffPruner()


@pytest.fixture
def client():
    return TestClient(app)


def test_should_prune_lockfiles(pruner: DiffPruner):
    lockfiles = [
        "package-lock.json",
        "frontend/yarn.lock",
        "backend/poetry.lock",
        "service/Cargo.lock",
        "api/go.sum",
        "Pipfile.lock",
    ]
    for path in lockfiles:
        should_prune, reason = pruner.should_prune_file(path)
        assert should_prune is True, f"Expected {path} to be pruned"
        assert "Lockfile" in reason


def test_should_prune_minified_and_compiled_bundles(pruner: DiffPruner):
    bundles = [
        "src/app.min.js",
        "static/css/styles.min.css",
        "bundle.chunk.js",
        "scripts/app.js.map",
    ]
    for path in bundles:
        should_prune, reason = pruner.should_prune_file(path)
        assert should_prune is True, f"Expected {path} to be pruned"
        assert "bundle" in reason.lower() or "minified" in reason.lower() or "map" in reason.lower()


def test_should_prune_vendor_directories(pruner: DiffPruner):
    vendor_files = [
        "node_modules/lodash/index.js",
        "vendor/bundle/ruby/2.7.0/gems/rake.rb",
        "dist/index.html",
        "build/static/js/main.js",
    ]
    for path in vendor_files:
        should_prune, reason = pruner.should_prune_file(path)
        assert should_prune is True, f"Expected {path} to be pruned"
        assert "vendor" in reason.lower() or "dist" in reason.lower() or "build" in reason.lower()


def test_should_prune_binary_and_media_assets(pruner: DiffPruner):
    assets = [
        "assets/logo.png",
        "public/hero.jpg",
        "images/icon.svg",
        "fonts/inter.woff2",
        "docs/whitepaper.pdf",
    ]
    for path in assets:
        should_prune, reason = pruner.should_prune_file(path)
        assert should_prune is True, f"Expected {path} to be pruned"
        assert "media/asset" in reason.lower()


def test_should_preserve_core_source_code(pruner: DiffPruner):
    sources = [
        "app/main.py",
        "src/components/Header.tsx",
        "controllers/user.js",
        "pkg/auth/token.go",
        "src/lib.rs",
        "db/migrations/001.sql",
        "Dockerfile",
        ".github/workflows/ci.yml",
    ]
    for path in sources:
        should_prune, reason = pruner.should_prune_file(path)
        assert should_prune is False, f"Source code {path} should NOT be pruned"
        assert reason is None


def test_prune_unified_diff_multi_file(pruner: DiffPruner):
    raw_diff = """diff --git a/app/main.py b/app/main.py
index 1234567..89abcdef 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,3 +1,5 @@
+def greet(name: str) -> str:
+    return f"Hello, {name}!"
diff --git a/package-lock.json b/package-lock.json
index abcdef1..2345678 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,10 +1,20 @@
+{
+  "name": "app",
+  "version": "1.0.0",
+  "lockfileVersion": 3,
+  "packages": {
+    "": {
+      "name": "app"
+    }
+  }
+}
diff --git a/dist/bundle.min.js b/dist/bundle.min.js
index fedcba9..8765432 100644
--- a/dist/bundle.min.js
+++ b/dist/bundle.min.js
@@ -1 +1 @@
-!function(e,t){}(this,function(){});
+!function(e,t){var n=1;}(this,function(){});
"""
    result = pruner.prune_diff(raw_diff)

    assert result.total_files_count == 3
    assert result.reviewed_files_count == 1
    assert result.pruned_files_count == 2
    assert "app/main.py" in result.reviewed_files
    assert any(p.filename == "package-lock.json" for p in result.pruned_files)
    assert any(p.filename == "dist/bundle.min.js" for p in result.pruned_files)

    # Clean diff contains ONLY app/main.py
    assert "def greet(name: str) -> str:" in result.clean_diff
    assert "package-lock.json" not in result.clean_diff
    assert "bundle.min.js" not in result.clean_diff

    # Metrics
    assert result.estimated_tokens_saved > 0
    assert result.reduction_percentage > 50.0


def test_empty_and_raw_snippet_handling(pruner: DiffPruner):
    assert pruner.prune_diff("").total_files_count == 0

    snippet = "def add(x, y): return x + y\n"
    res = pruner.prune_diff(snippet)
    assert res.total_files_count == 1
    assert res.reviewed_files_count == 1
    assert res.clean_diff == snippet


def test_api_review_endpoint_integrates_pruning(client: TestClient):
    """Verifies POST /api/v1/review/submit records pruning metrics on multi-file diffs."""
    diff_with_lockfile = """diff --git a/service.py b/service.py
--- a/service.py
+++ b/service.py
@@ -1,2 +1,3 @@
+def healthy():
+    return True
diff --git a/poetry.lock b/poetry.lock
--- a/poetry.lock
+++ b/poetry.lock
@@ -1,5 +1,10 @@
+[[package]]
+name = "cryptography"
+version = "42.0.5"
"""
    response = client.post(
        "/api/v1/review/submit",
        json={
            "code": diff_with_lockfile,
            "language": "python",
            "filename": "multi_diff.diff",
            "repo_name": "backend",
        },
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:dev@example.com"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["pruning_summary"] is not None
    assert data["pruning_summary"]["pruned_files_count"] == 1
    assert data["pruning_summary"]["reviewed_files_count"] == 1
    assert data["pruning_summary"]["tokens_saved_estimate"] > 0
