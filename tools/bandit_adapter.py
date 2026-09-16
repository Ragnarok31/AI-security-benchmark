"""
tools/bandit_adapter.py

Bandit security scanner adapter for the AI Security
Benchmark Suite.

WHAT BANDIT IS:
Bandit is a Python-specific static analysis tool that
builds an AST (Abstract Syntax Tree) from your code
and runs security checks against it. It ships with
~80 built-in checks covering SQL injection, hardcoded
passwords, weak crypto, shell injection, and more.

HOW THIS ADAPTER WORKS:
1. Runs bandit as a subprocess with JSON output
2. Parses the JSON into Finding objects
3. Returns list[Finding] to the benchmark engine

WHY SUBPROCESS AND NOT BANDIT'S PYTHON API?
Bandit has a Python API but it is considered internal
and changes between versions without warning. The CLI
with JSON output is stable and documented. Always
prefer the stable public interface.
"""

import subprocess
import json
import logging
from pathlib import Path
from models import Finding
from scanners import SecurityScanner, ToolNotAvailableError, ScanTimeoutError

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# BANDIT TEST NAME → VULNERABILITY TYPE MAPPING
# Maps Bandit's internal test names to our
# VulnerabilityType strings from models.py
# ─────────────────────────────────────────────

BANDIT_TEST_TO_VULN_TYPE = {
    # SQL Injection
    "hardcoded_sql_expressions":      "SQL_INJECTION",

    # Command Injection
    "subprocess_popen_with_shell_equals_true": "COMMAND_INJECTION",
    "subprocess_without_shell_equals_true":    "COMMAND_INJECTION",
    "start_process_with_shell_equals_true":    "COMMAND_INJECTION",
    "start_process_with_no_shell":             "COMMAND_INJECTION",
    "os_system":                               "COMMAND_INJECTION",

    # Hardcoded Secrets
    "hardcoded_password_string":      "HARDCODED_SECRET",
    "hardcoded_password_funcarg":     "HARDCODED_SECRET",
    "hardcoded_password_default":     "HARDCODED_SECRET",
    "hardcoded_bind_all_interfaces":  "HARDCODED_SECRET",

    # Weak Crypto / Insecure Deserialization
    "blacklist":                      "WEAK_CRYPTO",
    "pickle":                         "INSECURE_DESERIALIZATION",

    # Path Traversal
    "os_path_join":                   "PATH_TRAVERSAL",

    # XSS (Flask/Django specific)
    "flask_debug_true":               "XSS",
    "jinja2_autoescape_false":        "XSS",
}

# Default for unmapped test names
DEFAULT_VULN_TYPE = "UNKNOWN"


class BanditAdapter(SecurityScanner):
    """
    Adapter that runs Bandit and returns Finding objects.

    Usage:
        scanner = BanditAdapter(timeout=60)
        if scanner.is_available():
            result = scanner.run_scan("path/to/file.py")
            print(result.findings)
    """

    def get_name(self) -> str:
        """Return display name for leaderboard."""
        return "Bandit"

    def is_available(self) -> bool:
        """
        Check if Bandit is installed by running
        bandit --version. Returns True if exit
        code is 0, False otherwise.
        """
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            # bandit command not found on PATH
            return False
        except subprocess.TimeoutExpired:
            return False

    def scan(self, file_path: str) -> list[Finding]:
        """
        Run Bandit on a single Python file and return
        a list of Finding objects.

        Args:
            file_path: Path to the .py file to scan.

        Returns:
            list[Finding]: All findings Bandit detected.
                           Empty list if nothing found
                           or if scan fails.
        """
        path = Path(file_path)

        # ── Validate file exists ──
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        if not path.suffix == ".py":
            logger.warning(
                f"Bandit only scans .py files: {file_path}"
            )
            return []

        # ── Run Bandit as subprocess ──
        # CRITICAL: Never use shell=True here.
        # shell=True would allow command injection if
        # file_path contained malicious characters.
        # Always pass arguments as a list.
        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-r",           # recursive (handles single files too)
                    str(path),
                    "-f", "json",   # output format
                    "-l",           # include low severity
                    "-i",           # include low confidence
                    "--quiet",      # suppress info logs to stderr
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            raise ScanTimeoutError(
                f"Bandit timed out after {self.timeout}s "
                f"on {file_path}"
            )
        except FileNotFoundError:
            raise ToolNotAvailableError(
                "Bandit not found. Run: pip install bandit"
            )

        # ── Parse JSON output ──
        # Bandit exits with code 1 when it finds issues
        # and code 0 when it finds nothing.
        # Both are valid — we parse JSON either way.
        # Exit code > 1 means a real error occurred.
        if result.returncode > 1:
            logger.error(
                f"Bandit error on {file_path}: "
                f"{result.stderr[:200]}"
            )
            return []

        # ── Handle empty output ──
        if not result.stdout.strip():
            logger.warning(
                f"Bandit returned empty output for {file_path}"
            )
            return []

        # ── Parse JSON ──
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to parse Bandit JSON output: {e}"
            )
            return []

        # ── Convert results to Finding objects ──
        findings: list[Finding] = []

        for issue in output.get("results", []):
            try:
                finding = self._parse_issue(
                    issue=issue,
                    file_path=file_path
                )
                findings.append(finding)
            except (KeyError, ValueError) as e:
                logger.warning(
                    f"Skipping malformed Bandit issue: {e}"
                )
                continue

        logger.debug(
            f"Bandit found {len(findings)} issues in {file_path}"
        )
        return findings

    def _parse_issue(
        self,
        issue: dict,
        file_path: str
    ) -> Finding:
        """
        Convert a single Bandit JSON result entry
        into a Finding object.

        Args:
            issue:     One entry from Bandit's results[].
            file_path: Original file path scanned.

        Returns:
            Finding: Populated Finding object.
        """
        test_name = issue.get("test_name", "unknown")

        # Map Bandit test name to our vulnerability type
        vuln_type = BANDIT_TEST_TO_VULN_TYPE.get(
            test_name,
            DEFAULT_VULN_TYPE
        )

        # Normalize severity and confidence to uppercase
        severity   = issue.get(
            "issue_severity", "LOW"
        ).upper()

        confidence = issue.get(
            "issue_confidence", "LOW"
        ).upper()

        # Validate severity/confidence are valid values
        valid = {"HIGH", "MEDIUM", "LOW"}
        if severity not in valid:
            severity = "LOW"
        if confidence not in valid:
            confidence = "LOW"

        return Finding(
            tool_name=self.get_name(),
            file_path=file_path,
            line_number=issue.get("line_number", 0),
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            description=issue.get("issue_text", ""),
            raw_output={
                "test_id":   issue.get("test_id", ""),
                "test_name": test_name,
                "cwe":       issue.get("issue_cwe", {}),
                "code":      issue.get("code", ""),
                "more_info": issue.get("more_info", ""),
            }
        )