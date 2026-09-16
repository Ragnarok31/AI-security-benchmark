"""
tools/pipaudit_adapter.py

pip-audit security scanner adapter for the AI Security
Benchmark Suite.

WHAT PIP-AUDIT IS:
pip-audit scans Python dependencies for known CVEs
by checking installed packages against the Python
Packaging Advisory Database (PyPA) and the GitHub
Advisory Database (GHSA). Unlike Bandit and Semgrep
which scan code, pip-audit scans your requirements.txt
or installed packages for vulnerable versions.

HOW THIS ADAPTER WORKS:
This adapter is fundamentally different from Bandit
and Semgrep adapters. Instead of scanning a .py file
for code vulnerabilities, it scans a requirements.txt
file for dependency vulnerabilities.

When the benchmark engine passes a .py file path,
this adapter looks for a requirements.txt in the same
directory or the project root. If found, it scans
that instead.

WHY IS THIS USEFUL?
AI-generated code often includes import statements
for specific package versions. If that version has a
known CVE, pip-audit catches it. This is a completely
different attack surface from code quality — it is
supply chain security.
"""

import subprocess
import json
import logging
from pathlib import Path
from models import Finding
from scanners import (
    SecurityScanner,
    ToolNotAvailableError,
    ScanTimeoutError
)

logger = logging.getLogger(__name__)


class PipAuditAdapter(SecurityScanner):
    """
    Adapter that runs pip-audit and returns Finding objects.

    IMPORTANT DIFFERENCE:
    pip-audit scans requirements.txt files, not .py files.
    When given a .py file path, this adapter scans the
    project's requirements.txt instead.

    This means pip-audit findings are file-level
    (line_number = 0) rather than line-level like
    Bandit and Semgrep findings.

    Usage:
        scanner = PipAuditAdapter()
        if scanner.is_available():
            result = scanner.run_scan("requirements.txt")
            print(result.findings)
    """
    def __init__(self, timeout: int = 180):
        """Initialize with longer timeout.
        pip-audit queries external databases and
        scans many packages — needs more time than
        Bandit or Semgrep.
        """
        super().__init__(timeout=timeout)
	

    def get_name(self) -> str:
        """Return display name for leaderboard."""
        return "pip-audit"

    def is_available(self) -> bool:
        """
        Check if pip-audit is installed by running
        pip-audit --version.
        """
        try:
            result = subprocess.run(
                ["pip-audit", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except subprocess.TimeoutExpired:
            return False

    def _find_requirements_file(
        self,
        file_path: str
    ) -> Path | None:
        """
        Find the requirements.txt file to scan.

        Strategy:
        1. If file_path IS a requirements.txt, use it
        2. Check the same directory as file_path
        3. Check the project root (current directory)
        4. Return None if not found

        Args:
            file_path: Path passed by benchmark engine.

        Returns:
            Path to requirements.txt or None if not found.
        """
        path = Path(file_path)

        # If they passed requirements.txt directly
        if path.name == "requirements.txt" and path.exists():
            return path

        # Check same directory as the file
        sibling = path.parent / "requirements.txt"
        if sibling.exists():
            return sibling

        # Check project root (where we run from)
        root = Path("requirements.txt")
        if root.exists():
            return root

        return None

    def scan(self, file_path: str) -> list[Finding]:
        """
        Run pip-audit on a requirements.txt file and
        return a list of Finding objects.

        Args:
            file_path: Path to a .py file or
                      requirements.txt. Adapter finds
                      the right requirements.txt
                      automatically.

        Returns:
            list[Finding]: One Finding per vulnerable
                           dependency found.
                           Empty list if nothing found.
        """
        # ── Find requirements.txt ──
        req_file = self._find_requirements_file(file_path)

        if req_file is None:
            logger.warning(
                f"No requirements.txt found for {file_path}. "
                f"pip-audit skipping."
            )
            return []

        logger.debug(f"pip-audit scanning: {req_file}")

        # ── Run pip-audit as subprocess ──
        # -r → scan a requirements file
        # -f json → JSON output
        # --no-deps → don't resolve transitive dependencies
        #             (faster, focuses on direct deps)
        # NEVER use shell=True
        try:
            result = subprocess.run(
                [
                    "pip-audit",
                    "-r", str(req_file),
                    "-f", "json",
                    "--no-deps",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            raise ScanTimeoutError(
                f"pip-audit timed out after {self.timeout}s"
            )
        except FileNotFoundError:
            raise ToolNotAvailableError(
                "pip-audit not found. "
                "Run: pip install pip-audit"
            )

        # ── pip-audit exit codes ──
        # 0 → no vulnerabilities found
        # 1 → vulnerabilities found
        # Other → error
        if result.returncode not in (0, 1):
            logger.error(
                f"pip-audit error: {result.stderr[:200]}"
            )
            return []

        # ── Handle empty output ──
        stdout = result.stdout.strip()
        if not stdout:
            logger.warning("pip-audit returned empty output")
            return []

        # ── Parse JSON ──
        try:
            output = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to parse pip-audit JSON: {e}"
            )
            return []

        # ── Convert results to Finding objects ──
        findings: list[Finding] = []

        for dependency in output.get("dependencies", []):
            vulns = dependency.get("vulns", [])

            if not vulns:
                continue

            pkg_name    = dependency.get("name", "unknown")
            pkg_version = dependency.get("version", "unknown")

            for vuln in vulns:
                try:
                    finding = self._parse_vuln(
                        vuln=vuln,
                        pkg_name=pkg_name,
                        pkg_version=pkg_version,
                        req_file=str(req_file)
                    )
                    findings.append(finding)
                except (KeyError, ValueError) as e:
                    logger.warning(
                        f"Skipping malformed vuln entry: {e}"
                    )
                    continue

        if findings:
            logger.info(
                f"pip-audit found {len(findings)} "
                f"vulnerable dependencies in {req_file}"
            )
        else:
            logger.debug(
                f"pip-audit: no vulnerabilities in {req_file}"
            )

        return findings

    def _parse_vuln(
        self,
        vuln: dict,
        pkg_name: str,
        pkg_version: str,
        req_file: str
    ) -> Finding:
        """
        Convert a single pip-audit vulnerability entry
        into a Finding object.

        Args:
            vuln:        One vuln entry from pip-audit.
            pkg_name:    Name of the vulnerable package.
            pkg_version: Installed version of the package.
            req_file:    Path to the requirements file.

        Returns:
            Finding: Populated Finding object.
        """
        vuln_id     = vuln.get("id", "UNKNOWN")
        description = vuln.get("description", "")
        fix_versions = vuln.get("fix_versions", [])
        aliases     = vuln.get("aliases", [])

        # Extract CVE from aliases if available
        cve_id = next(
            (a for a in aliases if a.startswith("CVE-")),
            vuln_id
        )

        # Build human readable description
        fix_str = (
            f" Fix: upgrade to {fix_versions[0]}"
            if fix_versions else " No fix available."
        )
        full_description = (
            f"{pkg_name}=={pkg_version} has known "
            f"vulnerability {cve_id}.{fix_str} "
            f"{description[:100]}"
        )

        return Finding(
            tool_name=self.get_name(),
            file_path=req_file,
            line_number=0,
            vulnerability_type="DEPENDENCY_CVE",
            severity="HIGH",
            confidence="HIGH",
            description=full_description,
            raw_output={
                "package":      pkg_name,
                "version":      pkg_version,
                "vuln_id":      vuln_id,
                "cve":          cve_id,
                "fix_versions": fix_versions,
                "aliases":      aliases,
            }
        )