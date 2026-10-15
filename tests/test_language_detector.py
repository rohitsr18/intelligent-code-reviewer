import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.reviewer.language_detector import LanguageDetector


def test_detect_from_extension():
    ld = LanguageDetector()
    assert ld.detect("x = 1", filename="script.py").detected_language == "python"
    assert ld.detect("const a = 1", filename="index.ts").detected_language == "typescript"
    assert ld.detect("package main", filename="server.go").detected_language == "go"
    assert ld.detect("fn test() {}", filename="lib.rs").detected_language == "rust"
    assert ld.detect("class App {}", filename="Main.java").detected_language == "java"
    assert ld.detect("int main() {}", filename="main.cpp").detected_language == "cpp"
    assert ld.detect("FROM python:3.9", filename="Dockerfile").detected_language == "dockerfile"


def test_detect_from_diff_header():
    ld = LanguageDetector()
    diff = (
        "diff --git a/pkg/service.go b/pkg/service.go\n"
        "--- a/pkg/service.go\n"
        "+++ b/pkg/service.go\n"
        "@@ -1,2 +1,3 @@\n"
        "+package service\n"
    )
    res = ld.detect(diff)
    assert res.detected_language == "go"
    assert res.detected_by == "diff_header"
    assert res.confidence >= 0.95


def test_detect_from_shebang():
    ld = LanguageDetector()
    py_code = "#!/usr/bin/env python3\nprint('hello')\n"
    res_py = ld.detect(py_code)
    assert res_py.detected_language == "python"
    assert res_py.detected_by == "shebang"

    bash_code = "#!/bin/bash -e\necho 'running deployment'\n"
    res_bash = ld.detect(bash_code)
    assert res_bash.detected_language == "bash"
    assert res_bash.detected_by == "shebang"


def test_detect_from_code_syntax():
    ld = LanguageDetector()

    # Python
    py_code = (
        "import os\n"
        "def fetch_data(url: str):\n"
        "    if not url:\n"
        "        return None\n"
        "    return os.getenv('TOKEN')\n"
    )
    res_py = ld.detect(py_code)
    assert res_py.detected_language == "python"
    assert res_py.confidence >= 0.80

    # Go
    go_code = (
        "package main\n"
        "import \"fmt\"\n"
        "func main() {\n"
        "    fmt.Println(\"Hello World\")\n"
        "}\n"
    )
    res_go = ld.detect(go_code)
    assert res_go.detected_language == "go"
    assert res_go.confidence >= 0.85

    # Rust
    rs_code = (
        "fn calculate_hash(data: &str) -> String {\n"
        "    let mut hasher = DefaultHasher::new();\n"
        "    println!(\"Hashing\");\n"
        "}\n"
    )
    res_rs = ld.detect(rs_code)
    assert res_rs.detected_language == "rust"

    # TypeScript
    ts_code = (
        "interface UserProfile {\n"
        "    id: string;\n"
        "    active: boolean;\n"
        "}\n"
        "export const getUser = (id: string): UserProfile => {\n"
        "    return { id, active: true };\n"
        "};\n"
    )
    res_ts = ld.detect(ts_code)
    assert res_ts.detected_language == "typescript"

    # SQL
    sql_code = (
        "SELECT id, username, email\n"
        "FROM accounts\n"
        "WHERE active = 1 AND created_at >= '2026-01-01'\n"
        "ORDER BY id DESC;\n"
    )
    res_sql = ld.detect(sql_code)
    assert res_sql.detected_language == "sql"

    # JSON
    json_code = '{"name": "code-reviewer", "enabled": true, "version": 1}'
    res_json = ld.detect(json_code)
    assert res_json.detected_language == "json"


def test_detect_ambiguous():
    ld = LanguageDetector()
    ambig_code = "x = 10"
    res = ld.detect(ambig_code)
    assert res.is_ambiguous is True


@pytest.mark.asyncio
async def test_detect_language_api_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/review/detect-language",
            json={
                "code": "func RunServer(port int) error { return nil }",
                "filename": "server.go",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["detected_language"] == "go"
        assert data["confidence"] >= 0.9
        assert "python" in data["supported_languages"]


@pytest.mark.asyncio
async def test_review_submit_with_auto_language():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Code in Go with language="auto"
        go_code = (
            "package main\n"
            "import \"fmt\"\n"
            "func main() {\n"
            "    fmt.Println(\"Testing auto detect\")\n"
            "}\n"
        )
        resp = await client.post(
            "/api/v1/review/submit",
            json={
                "code": go_code,
                "language": "auto",
                "filename": "main.go",
            },
            headers={"X-Goog-Authenticated-User-Email": "dev@company.com"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["language"] == "go"
        assert data["detected_by"] in ("extension", "syntax_heuristic")

