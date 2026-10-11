from app.security.sanitizer import CodeSanitizer, calculate_shannon_entropy


def test_shannon_entropy_calculation():
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert calculate_shannon_entropy("9F81bK4mZ!0xLq92Vw8") > 3.8


def test_aws_access_key_redaction(sanitizer: CodeSanitizer):
    raw_code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nprint(AWS_KEY)'
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_code
    assert "<REDACTED_SECRET:AWS_ACCESS_KEY:1>" in result.sanitized_code
    assert len(result.redactions) == 1
    assert result.redactions[0].secret_type == "AWS_ACCESS_KEY"


def test_gcp_api_key_redaction(sanitizer: CodeSanitizer):
    raw_code = 'const gcpKey = "AIzaSyD-1234567890abcdefghijklmnopqrst";'
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "AIzaSyD" not in result.sanitized_code
    assert "<REDACTED_SECRET:GCP_API_KEY:1>" in result.sanitized_code


def test_github_token_redaction(sanitizer: CodeSanitizer):
    raw_code = 'token = "ghp_111122223333444455556666777788889999"'
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "ghp_1111" not in result.sanitized_code
    assert any("GITHUB_TOKEN" in r.secret_type or "ASSIGNED_CREDENTIAL" in r.secret_type for r in result.redactions)


def test_private_key_redaction(sanitizer: CodeSanitizer):
    raw_code = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3yZ2k...
...super_secret_payload...
-----END RSA PRIVATE KEY-----
"""
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "super_secret_payload" not in result.sanitized_code
    assert "<REDACTED_SECRET:PRIVATE_KEY:1>" in result.sanitized_code


def test_database_uri_password_redaction(sanitizer: CodeSanitizer):
    raw_code = 'DB_URI = "postgres://admin:super_secret_pass_123@db.prod.internal:5432/main"'
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "super_secret_pass_123" not in result.sanitized_code
    assert "<REDACTED_DB_PWD:1>" in result.sanitized_code
    assert 'DB_URI = "postgres://admin:<REDACTED_DB_PWD:1>@db.prod.internal:5432/main"' == result.sanitized_code


def test_assigned_password_redaction(sanitizer: CodeSanitizer):
    raw_code = 'db_password = "MySuperSecretPassword2024!"\napiKey = "xyzSecretKey12345"'
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "MySuperSecretPassword2024!" not in result.sanitized_code
    assert "xyzSecretKey12345" not in result.sanitized_code


def test_high_entropy_token_redaction(sanitizer: CodeSanitizer):
    raw_code = 'custom_auth = "u9T8z!qW7eR#2mY$vC*1xP&5sL@9"'
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "u9T8z!qW7eR#2mY$vC*1xP&5sL@9" not in result.sanitized_code


def test_pii_email_and_ip_redaction(sanitizer: CodeSanitizer):
    raw_code = """
# Developer: dev.engineer@acme-corp.com
REMOTE_HOST = "198.51.100.42"
LOCAL_HOST = "127.0.0.1"
"""
    result = sanitizer.sanitize(raw_code)
    assert result.has_pii is True
    assert "dev.engineer@acme-corp.com" not in result.sanitized_code
    assert "<REDACTED_PII:EMAIL:" in result.sanitized_code
    assert "198.51.100.42" not in result.sanitized_code
    assert "<REDACTED_PII:IP:" in result.sanitized_code
    # Loopback IP should not be touched
    assert "127.0.0.1" in result.sanitized_code


def test_slack_and_jwt_tokens(sanitizer: CodeSanitizer):
    raw_code = """
SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
"""
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert "xoxb-123456789012" not in result.sanitized_code
    assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in result.sanitized_code
    assert len(result.redactions) >= 2


def test_mixed_secrets_and_clean_context(sanitizer: CodeSanitizer):
    raw_code = """import os

# Database configuration
DB_PASS = "Prod_Database_P@ssw0rd!99"
AWS_KEY = "AKIA1234567890ABCDEF"

def connect():
    return f"Connecting with {AWS_KEY}"
"""
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is True
    assert result.original_line_count == 8
    assert "Prod_Database_P@ssw0rd!99" not in result.sanitized_code
    assert "AKIA1234567890ABCDEF" not in result.sanitized_code
    assert "def connect():" in result.sanitized_code
    assert 'return f"Connecting with {AWS_KEY}"' in result.sanitized_code
    assert 'AWS_KEY = "<REDACTED_SECRET:AWS_ACCESS_KEY:1>"' in result.sanitized_code


def test_empty_input(sanitizer: CodeSanitizer):
    result = sanitizer.sanitize("")
    assert result.original_line_count == 0
    assert result.sanitized_code == ""
    assert result.has_secrets is False
    assert result.has_pii is False


def test_clean_code_preservation(sanitizer: CodeSanitizer):
    raw_code = """def add_numbers(a: int, b: int) -> int:
    return a + b
"""
    result = sanitizer.sanitize(raw_code)
    assert result.has_secrets is False
    assert result.has_pii is False
    assert result.total_redactions == 0
    assert result.sanitized_code == raw_code
