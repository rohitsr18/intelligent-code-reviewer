"""Dependency & License Auditing Engine.

Performs static analysis on project package manifests and git diff additions:
1. Detects newly introduced or modified package dependencies across ecosystems
   (Python requirements.txt/pyproject.toml, Node package.json, Go go.mod,
   Rust Cargo.toml, Java pom.xml).
2. Audits dependency versions against curated CVE security advisory databases
   (e.g., Log4Shell, Spring4Shell, Lodash RCE, Requests/Urllib3 header leaks).
3. Enforces compliance against restrictive copyleft licenses (GPL, AGPL, SSPL)
   in proprietary commercial codebases.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import FindingCategory, FindingSeverity, ReviewFinding

logger = logging.getLogger(__name__)


class DiscoveredDependency(BaseModel):
    name: str
    version_spec: str
    parsed_version: Optional[str] = None
    ecosystem: str
    line_number: Optional[int] = None
    raw_line: Optional[str] = None


class VulnerabilityAdvisory(BaseModel):
    cve_id: str
    package: str
    ecosystem: str
    vulnerable_below: str
    severity: FindingSeverity
    title: str
    description: str
    fixed_version: str


class LicenseAdvisory(BaseModel):
    package: str
    license_spdx: str
    risk_level: FindingSeverity
    is_copyleft: bool
    description: str
    remediation: str


class DependencyFinding(BaseModel):
    package: str
    installed_version: str
    issue_type: str  # "cve" or "license"
    cve_id: Optional[str] = None
    severity: FindingSeverity
    title: str
    description: str
    remediation: str
    line_number: Optional[int] = None


class DependencyAuditResult(BaseModel):
    manifest_type: Optional[str] = None
    is_manifest: bool = False
    total_dependencies_scanned: int = 0
    vulnerable_packages_count: int = 0
    license_violations_count: int = 0
    dependencies: List[DiscoveredDependency] = Field(default_factory=list)
    findings: List[DependencyFinding] = Field(default_factory=list)

    def to_review_findings(self) -> List[ReviewFinding]:
        results: List[ReviewFinding] = []
        for f in self.findings:
            rule_prefix = "DEP" if f.issue_type == "cve" else "LIC"
            rule_id = f"{rule_prefix}-{f.cve_id or f.package.upper()}"
            results.append(
                ReviewFinding(
                    category=FindingCategory.SECURITY,
                    severity=f.severity,
                    title=f.title,
                    description=f"{f.description}\nRemediation: {f.remediation}",
                    line_start=f.line_number,
                    line_end=f.line_number,
                    suggested_fix=f.remediation,
                    rule_id=rule_id,
                    is_fix_valid=True,
                )
            )
        return results


def _parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """Extract integer version components for safe semver ordering (e.g. 'v4.17.15' -> (4, 17, 15))."""
    if not v_str:
        return (0, 0, 0)
    cleaned = re.sub(r"^[^\d]+", "", v_str.strip())
    parts = []
    for chunk in re.split(r"[.\-+]", cleaned):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _is_version_vulnerable(installed: str, vulnerable_below: str) -> bool:
    """Return True if installed version is strictly less than vulnerable_below."""
    inst_tuple = _parse_version_tuple(installed)
    target_tuple = _parse_version_tuple(vulnerable_below)
    return inst_tuple < target_tuple


# Curated Known Critical/High CVE Advisories Database
KNOWN_ADVISORIES: List[VulnerabilityAdvisory] = [
    # Python
    VulnerabilityAdvisory(
        cve_id="CVE-2023-45803",
        package="urllib3",
        ecosystem="pypi",
        vulnerable_below="2.0.7",
        severity=FindingSeverity.HIGH,
        title="urllib3: Sensitive Request Body Leaked on Cross-Origin Redirect",
        description="urllib3 does not remove request body content when redirecting with 303, potentially exposing secrets.",
        fixed_version=">=2.0.7",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2023-32681",
        package="requests",
        ecosystem="pypi",
        vulnerable_below="2.31.0",
        severity=FindingSeverity.HIGH,
        title="requests: Proxy-Authorization Header Leaked to Destination Server",
        description="requests forwards Proxy-Authorization headers when following redirects to unintended hosts.",
        fixed_version=">=2.31.0",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2024-27351",
        package="django",
        ecosystem="pypi",
        vulnerable_below="4.2.11",
        severity=FindingSeverity.HIGH,
        title="django: Regular Expression Denial of Service in Truncator",
        description="django.utils.text.Truncator suffers from catastrophic backtracking on untrusted user inputs.",
        fixed_version=">=4.2.11",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2023-48795",
        package="paramiko",
        ecosystem="pypi",
        vulnerable_below="3.4.0",
        severity=FindingSeverity.HIGH,
        title="paramiko: Terrapin Attack Protocol Sequence Truncation",
        description="Allows man-in-the-middle attackers to bypass integrity checks in SSH handshake.",
        fixed_version=">=3.4.0",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2024-26130",
        package="cryptography",
        ecosystem="pypi",
        vulnerable_below="42.0.4",
        severity=FindingSeverity.CRITICAL,
        title="cryptography: NULL Pointer Dereference in PKCS#12 Key Decryption",
        description="Passing encrypted keys without passwords triggers a fatal segmentation fault.",
        fixed_version=">=42.0.4",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2024-34064",
        package="jinja2",
        ecosystem="pypi",
        vulnerable_below="3.1.4",
        severity=FindingSeverity.HIGH,
        title="jinja2: Cross-Site Scripting (XSS) via Attribute Value Injection",
        description="HTML attribute keys containing spaces/slashes bypass autoescape protections.",
        fixed_version=">=3.1.4",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2024-30251",
        package="aiohttp",
        ecosystem="pypi",
        vulnerable_below="3.9.4",
        severity=FindingSeverity.HIGH,
        title="aiohttp: Denial of Service via Malformed Multipart Form Headers",
        description="Infinite parsing loop caused by malformed multipart boundary parsing.",
        fixed_version=">=3.9.4",
    ),
    # Node / NPM
    VulnerabilityAdvisory(
        cve_id="CVE-2021-23337",
        package="lodash",
        ecosystem="npm",
        vulnerable_below="4.17.21",
        severity=FindingSeverity.CRITICAL,
        title="lodash: Remote Code Execution via Template Command Injection",
        description="template functions allow arbitrary code injection through untrusted variable interpolation.",
        fixed_version="^4.17.21",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2023-45857",
        package="axios",
        ecosystem="npm",
        vulnerable_below="1.7.4",
        severity=FindingSeverity.HIGH,
        title="axios: Cross-Origin Header Leakage & SSRF",
        description="Critical authorization tokens retained across cross-origin redirect chains.",
        fixed_version="^1.7.4",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2024-29041",
        package="express",
        ecosystem="npm",
        vulnerable_below="4.19.2",
        severity=FindingSeverity.HIGH,
        title="express: Open Redirect via Malformed URI Encoded Paths",
        description="res.location and res.redirect accept malicious unencoded URLs leading to phishing redirection.",
        fixed_version="^4.19.2",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2022-23529",
        package="jsonwebtoken",
        ecosystem="npm",
        vulnerable_below="9.0.0",
        severity=FindingSeverity.CRITICAL,
        title="jsonwebtoken: Arbitrary File Write & Code Execution in verify()",
        description="Crafted keyStore object payloads allow arbitrary filesystem manipulation during verification.",
        fixed_version="^9.0.0",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2021-44906",
        package="minimist",
        ecosystem="npm",
        vulnerable_below="1.2.6",
        severity=FindingSeverity.CRITICAL,
        title="minimist: Prototype Pollution via Crafted CLI Arguments",
        description="Parsing arguments with '__proto__' modifies Object prototype globally.",
        fixed_version="^1.2.6",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2024-37890",
        package="ws",
        ecosystem="npm",
        vulnerable_below="8.17.1",
        severity=FindingSeverity.HIGH,
        title="ws: Denial of Service via Unhandled Continuation Frames",
        description="Crash triggered by unconstrained memory allocation during fragmented WebSocket message reception.",
        fixed_version="^8.17.1",
    ),
    # Java / Maven
    VulnerabilityAdvisory(
        cve_id="CVE-2021-44228",
        package="log4j-core",
        ecosystem="maven",
        vulnerable_below="2.17.1",
        severity=FindingSeverity.CRITICAL,
        title="log4j-core: Log4Shell Remote Code Execution (RCE) via JNDI Lookup",
        description="Untrusted user strings evaluated via JNDI lookups allow immediate zero-click remote shell execution.",
        fixed_version=">=2.17.1",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2022-22965",
        package="spring-core",
        ecosystem="maven",
        vulnerable_below="5.3.18",
        severity=FindingSeverity.CRITICAL,
        title="spring-core: Spring4Shell Remote Code Execution via DataBinder",
        description="Accessing classLoader via BeanWrapper allows arbitrary payload drop on web servers.",
        fixed_version=">=5.3.18",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2022-42889",
        package="commons-text",
        ecosystem="maven",
        vulnerable_below="1.10.0",
        severity=FindingSeverity.CRITICAL,
        title="commons-text: Text4Shell Arbitrary Code Execution via StringSubstitutor",
        description="StringSubstitutor interpolators (dns, url, script) trigger RCE on untrusted text.",
        fixed_version=">=1.10.0",
    ),
    # Go
    VulnerabilityAdvisory(
        cve_id="CVE-2023-39325",
        package="golang.org/x/net",
        ecosystem="golang",
        vulnerable_below="0.17.0",
        severity=FindingSeverity.HIGH,
        title="golang.org/x/net: HTTP/2 Rapid Reset DoS Attack",
        description="RST_STREAM frame flooding leads to instant CPU exhaustion and denial of service.",
        fixed_version="v0.17.0",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-2023-29401",
        package="github.com/gin-gonic/gin",
        ecosystem="golang",
        vulnerable_below="1.9.1",
        severity=FindingSeverity.HIGH,
        title="gin-gonic/gin: Server-Side Request Forgery via Insecure Redirects",
        description="c.Redirect accepts absolute path manipulation leading to SSRF.",
        fixed_version="v1.9.1",
    ),
]

# Known Restrictive Copyleft Packages (High Commercial/Proprietary Risk)
KNOWN_COPYLEFT_PACKAGES: Dict[str, LicenseAdvisory] = {
    "readline": LicenseAdvisory(
        package="readline",
        license_spdx="GPL-3.0",
        risk_level=FindingSeverity.HIGH,
        is_copyleft=True,
        description="GPL-3.0 enforces viral copyleft terms requiring proprietary derivative source code disclosure.",
        remediation="Replace with a permissive alternative such as 'prompt_toolkit' (BSD-3-Clause) or 'gnureadline'.",
    ),
    "ghostscript": LicenseAdvisory(
        package="ghostscript",
        license_spdx="AGPL-3.0",
        risk_level=FindingSeverity.CRITICAL,
        is_copyleft=True,
        description="AGPL-3.0 triggers network copyleft obligations for web/cloud services.",
        remediation="Use permissive PDF/PostScript alternatives like 'pdfminer.six' or 'pypdf' (MIT).",
    ),
    "mysql-connector-python": LicenseAdvisory(
        package="mysql-connector-python",
        license_spdx="GPL-2.0",
        risk_level=FindingSeverity.HIGH,
        is_copyleft=True,
        description="Official Oracle MySQL driver is licensed under strict GPL-2.0.",
        remediation="Use 'PyMySQL' (MIT) or 'aiomysql' (MIT) to prevent viral GPL licensing infectivity.",
    ),
    "wkhtmltopdf": LicenseAdvisory(
        package="wkhtmltopdf",
        license_spdx="LGPL-3.0",
        risk_level=FindingSeverity.MEDIUM,
        is_copyleft=True,
        description="LGPL-3.0 requires dynamic relinking mechanisms and distribution disclosures.",
        remediation="Migrate to headless Chromium/Playwright or WeasyPrint (BSD).",
    ),
    "mupdf": LicenseAdvisory(
        package="mupdf",
        license_spdx="AGPL-3.0",
        risk_level=FindingSeverity.CRITICAL,
        is_copyleft=True,
        description="MuPDF is licensed under AGPL-3.0; cloud usage forces source code disclosure.",
        remediation="Use 'pdfium' or 'pypdf' (BSD/MIT).",
    ),
}

RESTRICTIVE_LICENSES: Set[str] = {
    "GPL-1.0",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
    "SSPL-1.0",
    "EUPL-1.2",
    "OSL-3.0",
}


class DependencyAuditor:
    """Automated manifest dependency auditor for vulnerability & license compliance."""

    MANIFEST_EXTENSIONS = {
        "requirements.txt": "python_pip",
        "requirements-dev.txt": "python_pip",
        "pyproject.toml": "python_pyproject",
        "pipfile": "python_pipfile",
        "package.json": "node_package_json",
        "package-lock.json": "node_package_lock",
        "go.mod": "go_mod",
        "cargo.toml": "rust_cargo",
        "pom.xml": "java_maven",
        "build.gradle": "java_gradle",
    }

    def detect_manifest_type(self, filename: Optional[str], content: str) -> Optional[str]:
        """Detect manifest type from filename or file content syntax."""
        if filename:
            base = filename.lower().split("/")[-1].split("\\")[-1]
            if base in self.MANIFEST_EXTENSIONS:
                return self.MANIFEST_EXTENSIONS[base]
            if base.endswith(".txt") and "requirements" in base:
                return "python_pip"

        # Heuristic detection from content
        stripped = content.strip()
        if (
            '"dependencies"' in stripped
            or '"devDependencies"' in stripped
            or ('"name":' in stripped and '"version":' in stripped and "{" in stripped)
        ):
            return "node_package_json"
        if "module " in stripped and "go " in stripped and "require (" in stripped:
            return "go_mod"
        if "[dependencies]" in stripped or "[package]" in stripped and "name =" in stripped:
            return "rust_cargo"
        if "<project" in stripped and "<dependencies>" in stripped:
            return "java_maven"
        # Pip pattern: lines with package==version or package>=version
        pip_matches = re.findall(r"^[a-zA-Z0-9_\-\.]+([=><~]=?)[0-9\.]+", content, re.MULTILINE)
        if len(pip_matches) >= 2 or (len(pip_matches) >= 1 and len(content.splitlines()) <= 5):
            return "python_pip"

        return None

    def _parse_pip_dependencies(self, content: str) -> List[DiscoveredDependency]:
        """Extract Python dependencies from requirements.txt or pip diff lines."""
        results: List[DiscoveredDependency] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            raw = line.strip()
            # Handle diff additions
            if raw.startswith("+") and not raw.startswith("+++"):
                raw = raw[1:].strip()

            if not raw or raw.startswith("#") or raw.startswith("-"):
                continue

            # e.g., requests==2.20.0 or urllib3>=1.26.0,<2.0.0
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~]=?)\s*([0-9\.\w\-]+)", raw)
            if m:
                pkg_name = m.group(1).lower()
                op = m.group(2)
                ver = m.group(3)
                results.append(
                    DiscoveredDependency(
                        name=pkg_name,
                        version_spec=f"{op}{ver}",
                        parsed_version=ver,
                        ecosystem="pypi",
                        line_number=idx,
                        raw_line=line,
                    )
                )
        return results

    def _parse_npm_dependencies(self, content: str) -> List[DiscoveredDependency]:
        """Extract Node.js dependencies from package.json or git diff."""
        results: List[DiscoveredDependency] = []
        lines = content.splitlines()

        # Check if full JSON structure
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
                    deps = data.get(dep_key, {})
                    if isinstance(deps, dict):
                        for pkg, ver in deps.items():
                            clean_ver = re.sub(r"^[^\d]+", "", str(ver))
                            results.append(
                                DiscoveredDependency(
                                    name=pkg.lower(),
                                    version_spec=str(ver),
                                    parsed_version=clean_ver,
                                    ecosystem="npm",
                                    raw_line=f'"{pkg}": "{ver}"',
                                )
                            )
                return results
        except Exception:
            pass

        # Regex parsing for partial diff additions
        for idx, line in enumerate(lines, start=1):
            raw = line.strip()
            if raw.startswith("+") and not raw.startswith("+++"):
                raw = raw[1:].strip()

            m = re.search(r'"([@a-zA-Z0-9_\-\/]+)"\s*:\s*"([^"]+)"', raw)
            if m:
                pkg = m.group(1).lower()
                ver = m.group(2)
                clean_ver = re.sub(r"^[^\d]+", "", ver)
                # Ignore metadata fields like scripts, name, version, main
                if pkg not in ("name", "version", "main", "author", "license", "description"):
                    results.append(
                        DiscoveredDependency(
                            name=pkg,
                            version_spec=ver,
                            parsed_version=clean_ver,
                            ecosystem="npm",
                            line_number=idx,
                            raw_line=line,
                        )
                    )
        return results

    def _parse_go_dependencies(self, content: str) -> List[DiscoveredDependency]:
        """Extract Go dependencies from go.mod or diff lines."""
        results: List[DiscoveredDependency] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            raw = line.strip()
            if raw.startswith("+") and not raw.startswith("+++"):
                raw = raw[1:].strip()

            # e.g. github.com/gin-gonic/gin v1.8.0 or require (...)
            m = re.search(r"^\s*(?:require\s+)?([a-zA-Z0-9_\-\.\/]+)\s+v?([0-9\.\w\-]+)", raw)
            if m:
                pkg = m.group(1)
                ver = m.group(2)
                if pkg != "module" and pkg != "go":
                    results.append(
                        DiscoveredDependency(
                            name=pkg,
                            version_spec=ver,
                            parsed_version=ver,
                            ecosystem="golang",
                            line_number=idx,
                            raw_line=line,
                        )
                    )
        return results

    def _parse_maven_dependencies(self, content: str) -> List[DiscoveredDependency]:
        """Extract Maven dependencies from pom.xml."""
        results: List[DiscoveredDependency] = []
        dep_blocks = re.findall(
            r"<dependency>(.*?)</dependency>", content, re.DOTALL | re.IGNORECASE
        )
        for block in dep_blocks:
            art = re.search(r"<artifactId>(.*?)</artifactId>", block, re.IGNORECASE)
            ver = re.search(r"<version>(.*?)</version>", block, re.IGNORECASE)
            if art:
                pkg = art.group(1).strip()
                v_str = ver.group(1).strip() if ver else "0.0.0"
                results.append(
                    DiscoveredDependency(
                        name=pkg.lower(),
                        version_spec=v_str,
                        parsed_version=v_str,
                        ecosystem="maven",
                        raw_line=block.strip(),
                    )
                )
        return results

    def _parse_cargo_dependencies(self, content: str) -> List[DiscoveredDependency]:
        """Extract Rust dependencies from Cargo.toml."""
        results: List[DiscoveredDependency] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            raw = line.strip()
            if raw.startswith("+") and not raw.startswith("+++"):
                raw = raw[1:].strip()

            m = re.match(r"^([a-zA-Z0-9_\-]+)\s*=\s*\"([^\"]+)\"", raw)
            if m:
                pkg = m.group(1).lower()
                ver = m.group(2)
                if pkg not in ("name", "version", "edition", "authors"):
                    clean_ver = re.sub(r"^[^\d]+", "", ver)
                    results.append(
                        DiscoveredDependency(
                            name=pkg,
                            version_spec=ver,
                            parsed_version=clean_ver,
                            ecosystem="crates",
                            line_number=idx,
                            raw_line=line,
                        )
                    )
        return results

    def audit_dependencies(
        self,
        code_or_diff: str,
        filename: Optional[str] = None,
    ) -> DependencyAuditResult:
        """Scan code or diff for dependencies, auditing against known CVEs and copyleft licenses."""
        m_type = self.detect_manifest_type(filename, code_or_diff)
        if not m_type:
            return DependencyAuditResult(
                manifest_type=None,
                is_manifest=False,
                total_dependencies_scanned=0,
                vulnerable_packages_count=0,
                license_violations_count=0,
                dependencies=[],
                findings=[],
            )

        discovered: List[DiscoveredDependency] = []
        if m_type == "python_pip" or m_type == "python_pyproject":
            discovered.extend(self._parse_pip_dependencies(code_or_diff))
        elif m_type == "node_package_json" or m_type == "node_package_lock":
            discovered.extend(self._parse_npm_dependencies(code_or_diff))
        elif m_type == "go_mod":
            discovered.extend(self._parse_go_dependencies(code_or_diff))
        elif m_type == "java_maven":
            discovered.extend(self._parse_maven_dependencies(code_or_diff))
        elif m_type == "rust_cargo":
            discovered.extend(self._parse_cargo_dependencies(code_or_diff))

        findings: List[DependencyFinding] = []

        # 1. Audit against CVE Security Advisories
        for dep in discovered:
            for adv in KNOWN_ADVISORIES:
                if adv.package.lower() == dep.name.lower():
                    # Check version
                    if dep.parsed_version and _is_version_vulnerable(dep.parsed_version, adv.vulnerable_below):
                        findings.append(
                            DependencyFinding(
                                package=dep.name,
                                installed_version=dep.version_spec,
                                issue_type="cve",
                                cve_id=adv.cve_id,
                                severity=adv.severity,
                                title=f"[{adv.cve_id}] {adv.title}",
                                description=f"Installed {dep.name} ({dep.version_spec}) is vulnerable to {adv.cve_id}: {adv.description}",
                                remediation=f"Upgrade {dep.name} to {adv.fixed_version} or higher immediately.",
                                line_number=dep.line_number,
                            )
                        )

        # 2. Audit against Restrictive Copyleft Licenses
        for dep in discovered:
            if dep.name.lower() in KNOWN_COPYLEFT_PACKAGES:
                lic_adv = KNOWN_COPYLEFT_PACKAGES[dep.name.lower()]
                findings.append(
                    DependencyFinding(
                        package=dep.name,
                        installed_version=dep.version_spec,
                        issue_type="license",
                        cve_id=None,
                        severity=lic_adv.risk_level,
                        title=f"[License Risk: {lic_adv.license_spdx}] Restrictive Copyleft Dependency: {dep.name}",
                        description=f"Package '{dep.name}' is distributed under {lic_adv.license_spdx}. {lic_adv.description}",
                        remediation=lic_adv.remediation,
                        line_number=dep.line_number,
                    )
                )

        # Check explicit license fields inside package.json
        if m_type in ("node_package_json", "python_pyproject"):
            lic_match = re.search(r'"license"\s*:\s*"([^"]+)"', code_or_diff, re.IGNORECASE)
            if lic_match:
                lic_name = lic_match.group(1).upper()
                for bad_lic in RESTRICTIVE_LICENSES:
                    if bad_lic in lic_name:
                        findings.append(
                            DependencyFinding(
                                package="project_manifest",
                                installed_version=lic_name,
                                issue_type="license",
                                cve_id=None,
                                severity=FindingSeverity.HIGH,
                                title=f"[License Policy Violation] Restrictive License Declared: {lic_name}",
                                description=f"Manifest declares '{lic_name}'. Viral copyleft licenses are disallowed in proprietary commercial codebases.",
                                remediation="Switch project license to a permissive standard such as MIT or Apache-2.0.",
                                line_number=None,
                            )
                        )
                        break

        vulnerable_count = sum(1 for f in findings if f.issue_type == "cve")
        license_count = sum(1 for f in findings if f.issue_type == "license")

        return DependencyAuditResult(
            manifest_type=m_type,
            is_manifest=True,
            total_dependencies_scanned=len(discovered),
            vulnerable_packages_count=vulnerable_count,
            license_violations_count=license_count,
            dependencies=discovered,
            findings=findings,
        )
