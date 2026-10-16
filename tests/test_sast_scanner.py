"""Unit and integration tests for AST-based SAST Vulnerability Scanner."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reviewer.models import FindingSeverity
from app.reviewer.sast_scanner import SASTScanner


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def scanner():
    return SASTScanner()


def test_sast_detects_python_sqli_fstring(scanner):
    code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()
"""
    res = scanner.scan(code, language="python", filename="query.py")
    assert res.total_findings >= 1
    assert res.critical_count >= 1
    sqli = next(f for f in res.findings if f.rule_id == "SEC-PY-SQLI-001")
    assert sqli.cwe_id == "CWE-89"
    assert sqli.severity == FindingSeverity.CRITICAL
    assert sqli.line_number == 7


def test_sast_detects_python_sqli_concat(scanner):
    code = """
def run_query(cursor, name):
    cursor.execute("SELECT * FROM products WHERE name = '" + name + "'")
"""
    res = scanner.scan(code, language="python")
    assert any(f.rule_id == "SEC-PY-SQLI-002" for f in res.findings)


def test_sast_detects_command_injection_subprocess_shell_true(scanner):
    code = """
import subprocess

def ping(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)
"""
    res = scanner.scan(code, language="python")
    cmd_inj = next(f for f in res.findings if f.rule_id == "SEC-PY-CMD-001")
    assert cmd_inj.cwe_id == "CWE-78"
    assert cmd_inj.severity == FindingSeverity.CRITICAL
    assert cmd_inj.line_number == 5


def test_sast_detects_os_system_command_injection(scanner):
    code = """
import os

def delete_file(filename):
    os.system("rm -rf " + filename)
"""
    res = scanner.scan(code, language="python")
    assert any(f.rule_id == "SEC-PY-CMD-002" for f in res.findings)


def test_sast_detects_insecure_deserialization_pickle(scanner):
    code = """
import pickle

def load_payload(raw_bytes):
    return pickle.loads(raw_bytes)
"""
    res = scanner.scan(code, language="python")
    pickle_finding = next(f for f in res.findings if f.rule_id == "SEC-PY-DESER-001")
    assert pickle_finding.cwe_id == "CWE-502"
    assert pickle_finding.severity == FindingSeverity.CRITICAL


def test_sast_detects_insecure_yaml_load(scanner):
    code = """
import yaml

def parse_config(data):
    return yaml.load(data)
"""
    res = scanner.scan(code, language="python")
    yaml_finding = next(f for f in res.findings if f.rule_id == "SEC-PY-DESER-002")
    assert yaml_finding.cwe_id == "CWE-502"
    assert yaml_finding.severity == FindingSeverity.HIGH


def test_sast_detects_arbitrary_eval_exec(scanner):
    code = """
def evaluate_math(user_expr):
    return eval(user_expr)
"""
    res = scanner.scan(code, language="python")
    eval_finding = next(f for f in res.findings if f.rule_id == "SEC-PY-CODEINJ-001")
    assert eval_finding.cwe_id == "CWE-95"
    assert eval_finding.severity == FindingSeverity.CRITICAL


def test_sast_detects_weak_hash_md5(scanner):
    code = """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
    res = scanner.scan(code, language="python")
    md5_finding = next(f for f in res.findings if f.rule_id == "SEC-PY-CRYPTO-001")
    assert md5_finding.cwe_id == "CWE-327"
    assert md5_finding.severity == FindingSeverity.MEDIUM


def test_sast_detects_insecure_random_for_token(scanner):
    code = """
import random

def generate_session_token():
    auth_token = str(random.random())
    return auth_token
"""
    res = scanner.scan(code, language="python")
    rand_finding = next(f for f in res.findings if f.rule_id == "SEC-PY-RAND-001")
    assert rand_finding.cwe_id == "CWE-338"
    assert rand_finding.severity == FindingSeverity.HIGH


def test_sast_detects_insecure_tempfile(scanner):
    code = """
import tempfile

def create_scratch():
    path = tempfile.mktemp()
    return path
"""
    res = scanner.scan(code, language="python")
    temp_finding = next(f for f in res.findings if f.rule_id == "SEC-PY-TEMP-001")
    assert temp_finding.cwe_id == "CWE-377"


def test_sast_detects_hardcoded_aws_and_github_secrets(scanner):
    code = """
AWS_KEY = "AKIA1234567890ABCDEF"
GITHUB_PAT = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
"""
    res = scanner.scan(code, language="python")
    assert any(f.rule_id == "SEC-KEY-AWS-001" for f in res.findings)
    assert any(f.rule_id == "SEC-KEY-GH-001" for f in res.findings)


def test_sast_detects_javascript_sqli_and_command_injection(scanner):
    js_code = """
const { exec } = require('child_process');

function handleRequest(req, res) {
    const userId = req.query.id;
    db.query(`SELECT * FROM users WHERE id = ${userId}`);
    exec("ping " + req.query.ip);
}
"""
    res = scanner.scan(js_code, language="javascript", filename="handler.js")
    assert res.total_findings >= 2
    assert any(f.rule_id == "SEC-JS-SQLI-001" for f in res.findings)
    assert any(f.rule_id == "SEC-JS-CMD-001" for f in res.findings)


def test_sast_detects_go_command_injection(scanner):
    go_code = """
package main
import (
    "fmt"
    "os/exec"
)

func run(input string) {
    cmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s", input))
    cmd.Run()
}
"""
    res = scanner.scan(go_code, language="go", filename="main.go")
    assert any(f.rule_id == "SEC-GO-CMD-001" for f in res.findings)


def test_scan_sast_api_endpoint(client):
    payload = {
        "code": "cursor.execute(f'SELECT * FROM accounts WHERE id = {acc_id}')",
        "language": "python",
        "filename": "repo.py",
    }
    resp = client.post("/api/v1/review/scan-sast", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["language"] == "python"
    assert data["total_findings"] >= 1
    assert data["critical_count"] >= 1
    assert any(f["cwe_id"] == "CWE-89" for f in data["findings"])


def test_submit_code_for_review_integrates_sast_findings(client):
    vulnerable_code = """
import pickle

def deserialize(data):
    return pickle.loads(data)
"""
    resp = client.post(
        "/api/v1/review/submit",
        json={"code": vulnerable_code, "language": "python", "filename": "app.py"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["sast_summary"] is not None
    assert data["sast_summary"]["critical_count"] >= 1
    # Analysis findings contain the SAST finding
    assert any("CWE-502" in f["title"] for f in data["analysis"]["findings"])
    # Security score calibrated down
    assert data["analysis"]["category_scores"]["security"] <= 70
