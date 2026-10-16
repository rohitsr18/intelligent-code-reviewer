import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.reviewer.dependency_auditor import (
    DependencyAuditor,
    _is_version_vulnerable,
    _parse_version_tuple,
)
from app.reviewer.models import FindingSeverity


@pytest.fixture
def client():
    return TestClient(app)


def test_version_tuple_parsing():
    assert _parse_version_tuple("1.2.3") == (1, 2, 3)
    assert _parse_version_tuple("v2.31.0") == (2, 31, 0)
    assert _parse_version_tuple("4.17.15-alpha") == (4, 17, 15)
    assert _parse_version_tuple("10") == (10, 0, 0)


def test_version_vulnerability_checker():
    # 2.20.0 is vulnerable if below 2.31.0
    assert _is_version_vulnerable("2.20.0", "2.31.0") is True
    # 2.31.0 is safe
    assert _is_version_vulnerable("2.31.0", "2.31.0") is False
    # 2.32.0 is safe
    assert _is_version_vulnerable("2.32.0", "2.31.0") is False
    # 4.17.20 < 4.17.21
    assert _is_version_vulnerable("4.17.20", "4.17.21") is True
    assert _is_version_vulnerable("4.17.21", "4.17.21") is False


def test_non_manifest_code_returns_empty():
    auditor = DependencyAuditor()
    code = "def calculate_tax(amount):\n    return amount * 0.15\n"
    res = auditor.audit_dependencies(code, filename="service.py")
    assert res.is_manifest is False
    assert res.total_dependencies_scanned == 0
    assert len(res.findings) == 0


def test_audit_python_requirements_with_vulnerable_packages():
    auditor = DependencyAuditor()
    content = """
    # Production dependencies
    requests==2.20.0
    urllib3==1.25.8
    fastapi==0.110.0
    """
    res = auditor.audit_dependencies(content, filename="requirements.txt")
    assert res.is_manifest is True
    assert res.manifest_type == "python_pip"
    assert res.total_dependencies_scanned == 3
    assert res.vulnerable_packages_count == 2

    cves = [f.cve_id for f in res.findings if f.cve_id]
    assert "CVE-2023-32681" in cves  # requests
    assert "CVE-2023-45803" in cves  # urllib3

    review_findings = res.to_review_findings()
    assert len(review_findings) == 2
    assert review_findings[0].category.value == "security"
    assert "Upgrade" in review_findings[0].suggested_fix


def test_audit_clean_python_requirements():
    auditor = DependencyAuditor()
    content = """
    requests>=2.31.0
    urllib3>=2.0.7
    fastapi>=0.110.0
    """
    res = auditor.audit_dependencies(content, filename="requirements.txt")
    assert res.is_manifest is True
    assert res.total_dependencies_scanned == 3
    assert res.vulnerable_packages_count == 0
    assert len(res.findings) == 0


def test_audit_node_package_json_vulnerabilities():
    auditor = DependencyAuditor()
    package_json = """{
      "name": "sample-service",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.15",
        "express": "4.18.0",
        "react": "18.2.0"
      }
    }"""
    res = auditor.audit_dependencies(package_json, filename="package.json")
    assert res.is_manifest is True
    assert res.manifest_type == "node_package_json"
    assert res.vulnerable_packages_count >= 2

    lodash_finding = next((f for f in res.findings if f.package == "lodash"), None)
    assert lodash_finding is not None
    assert lodash_finding.cve_id == "CVE-2021-23337"
    assert lodash_finding.severity == FindingSeverity.CRITICAL


def test_audit_diff_additions_in_package_json():
    auditor = DependencyAuditor()
    diff = """
    --- a/package.json
    +++ b/package.json
    @@ -15,2 +15,3 @@
    +    "lodash": "^4.17.10",
    +    "axios": "1.5.0",
         "react": "^18.2.0"
    """
    res = auditor.audit_dependencies(diff, filename="package.json")
    assert res.is_manifest is True
    assert res.vulnerable_packages_count >= 2
    pkgs = [d.name for d in res.dependencies]
    assert "lodash" in pkgs
    assert "axios" in pkgs


def test_audit_java_pom_xml_log4shell():
    auditor = DependencyAuditor()
    pom_xml = """<project>
      <dependencies>
        <dependency>
          <groupId>org.apache.logging.log4j</groupId>
          <artifactId>log4j-core</artifactId>
          <version>2.14.1</version>
        </dependency>
      </dependencies>
    </project>"""
    res = auditor.audit_dependencies(pom_xml, filename="pom.xml")
    assert res.is_manifest is True
    assert res.manifest_type == "java_maven"
    assert res.vulnerable_packages_count == 1
    f = res.findings[0]
    assert f.cve_id == "CVE-2021-44228"
    assert f.severity == FindingSeverity.CRITICAL


def test_audit_go_mod_vulnerabilities():
    auditor = DependencyAuditor()
    go_mod = """module example.com/service

    go 1.21

    require (
        github.com/gin-gonic/gin v1.8.0
        golang.org/x/net v0.10.0
    )"""
    res = auditor.audit_dependencies(go_mod, filename="go.mod")
    assert res.is_manifest is True
    assert res.manifest_type == "go_mod"
    assert res.vulnerable_packages_count >= 1
    assert any("CVE-2023-39325" in str(f.cve_id) for f in res.findings)


def test_audit_copyleft_gpl_license_detection():
    auditor = DependencyAuditor()
    content = """
    readline==8.2
    ghostscript==0.7.0
    requests==2.31.0
    """
    res = auditor.audit_dependencies(content, filename="requirements.txt")
    assert res.is_manifest is True
    assert res.license_violations_count == 2
    lic_findings = [f for f in res.findings if f.issue_type == "license"]
    assert len(lic_findings) == 2
    pkgs = [f.package for f in lic_findings]
    assert "readline" in pkgs
    assert "ghostscript" in pkgs


def test_audit_manifest_level_license_declaration():
    auditor = DependencyAuditor()
    pkg_json = """{
      "name": "internal-tool",
      "version": "1.0.0",
      "license": "AGPL-3.0",
      "dependencies": {
        "react": "18.2.0"
      }
    }"""
    res = auditor.audit_dependencies(pkg_json, filename="package.json")
    assert res.license_violations_count == 1
    assert "AGPL-3.0" in res.findings[0].title


def test_review_endpoint_audit_dependencies_route(client: TestClient):
    payload = {
        "manifest_content": "requests==2.20.0\nurllib3==1.25.8\n",
        "filename": "requirements.txt",
    }
    response = client.post(
        "/api/v1/review/audit-dependencies",
        json=payload,
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:engineer@company.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_manifest"] is True
    assert data["manifest_type"] == "python_pip"
    assert data["total_dependencies_scanned"] == 2
    assert data["vulnerable_packages_count"] == 2
    assert len(data["findings"]) == 2


def test_submit_code_for_review_integrates_dependency_findings(client: TestClient):
    # Submitting requirements.txt with vulnerable packages
    content = "requests==2.20.0\n"
    response = client.post(
        "/api/v1/review/submit",
        json={
            "code": content,
            "filename": "requirements.txt",
            "language": "auto",
        },
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:engineer@company.com"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["dependency_audit"] is not None
    assert data["dependency_audit"]["vulnerable_packages_count"] >= 1

    # Findings should contain the CVE security issue
    findings = data["analysis"]["findings"]
    cve_findings = [f for f in findings if "CVE-2023-32681" in f["title"]]
    assert len(cve_findings) >= 1
    assert cve_findings[0]["category"] == "security"
