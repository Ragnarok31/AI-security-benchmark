"""
tools/semgrep_adapter.py

Semgrep security scanner adapter for the AI Security
Benchmark Suite.

WHAT SEMGREP IS:
Semgrep is a pattern-based static analysis tool that
matches code patterns against a library of security
rules. Unlike Bandit which uses Python's AST,
Semgrep uses its own pattern language that works
across 30+ languages. It supports taint tracking
(following user input through code paths) which
lets it catch vulnerabilities Bandit misses.

HOW THIS ADAPTER WORKS:
1. Runs semgrep as a subprocess with JSON output
2. Parses the JSON into Finding objects
3. Returns list[Finding] to the benchmark engine

KEY DIFFERENCE FROM BANDIT:
Semgrep's severity uses "WARNING"/"ERROR"/"INFO"
We map these to our "HIGH"/"MEDIUM"/"LOW" strings.
"""

import subprocess
import json
import logging
import re
from pathlib import Path
from models import Finding
from scanners import (
    SecurityScanner,
    ToolNotAvailableError,
    ScanTimeoutError
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# SEVERITY MAPPING
# Semgrep uses WARNING/ERROR/INFO
# We use HIGH/MEDIUM/LOW
# ─────────────────────────────────────────────

SEMGREP_SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}

# ─────────────────────────────────────────────
# CONFIDENCE MAPPING
# Semgrep metadata uses HIGH/MEDIUM/LOW already
# but sometimes missing — default to MEDIUM
# ─────────────────────────────────────────────

VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}

# ─────────────────────────────────────────────
# CWE → VULNERABILITY TYPE MAPPING
# Semgrep returns CWE as "CWE-89: Improper..."
# We extract the number and map to our types
# ─────────────────────────────────────────────

CWE_TO_VULN_TYPE = {
    "89":  "SQL_INJECTION",
    "79":  "XSS",
    "78":  "COMMAND_INJECTION",
    "77":  "COMMAND_INJECTION",
    "22":  "PATH_TRAVERSAL",
    "502": "INSECURE_DESERIALIZATION",
    "798": "HARDCODED_SECRET",
    "94":  "COMMAND_INJECTION",
    "489": "XSS",
    "704": "SQL_INJECTION",
}

DEFAULT_VULN_TYPE = "UNKNOWN"


def extract_cwe_number(cwe_string: str) -> str:
    """
    Extract the numeric part from a CWE string.

    Semgrep returns: "CWE-89: Improper Neutralization..."
    We want just:   "89"

    Args:
        cwe_string: Full CWE string from Semgrep metadata.

    Returns:
        str: The numeric CWE ID, or empty string if
             no match found.

    Example:
        extract_cwe_number("CWE-89: SQL Injection") → "89"
    """
    match = re.search(r'CWE-(\d+)', cwe_string)
    return match.group(1) if match else ""


class SemgrepAdapter(SecurityScanner):
    """
    Adapter that runs Semgrep and returns Finding objects.

    Usage:
        scanner = SemgrepAdapter(timeout=120)
        if scanner.is_available():
            result = scanner.run_scan("path/to/file.py")
            print(result.findings)

    NOTE ON TIMEOUT:
    Semgrep is slower than Bandit because it downloads
    rules and does deeper analysis. Default timeout is
    90 seconds (overrides parent's 60s default).
    """

    def __init__(self, timeout: int = 120):
        """Initialize with longer default timeout."""
        super().__init__(timeout=timeout)

    def get_name(self) -> str:
        """Return display name for leaderboard."""
        return "Semgrep"

    def is_available(self) -> bool:
        """
        Check if Semgrep is installed by running
        semgrep --version.
        """
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except subprocess.TimeoutExpired:
            return False

    def scan(self, file_path: str) -> list[Finding]:
        """
        Run Semgrep on a single Python file and return
        a list of Finding objects.

        Args:
            file_path: Path to the .py file to scan.

        Returns:
            list[Finding]: All findings Semgrep detected.
                           Empty list if nothing found
                           or if scan fails.
        """
        path = Path(file_path)

        # ── Validate file exists ──
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        # ── Run Semgrep as subprocess ──
        # --config p/python uses Python-specific ruleset
        # --json outputs machine-readable JSON
        # --quiet suppresses progress output
        # --no-autofix prevents any code modification
        # NEVER use shell=True
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", "p/python",
                    "--json",
                    "--quiet",
                    "--no-autofix",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            raise ScanTimeoutError(
                f"Semgrep timed out after {self.timeout}s "
                f"on {file_path}"
            )
        except FileNotFoundError:
            raise ToolNotAvailableError(
                "Semgrep not found. Run: pip install semgrep"
            )

        # ── Handle errors ──
        # Semgrep exit codes:
        # 0 → success, no findings
        # 1 → success, findings found
        # 2 → fatal error
        if result.returncode == 2:
            logger.error(
                f"Semgrep fatal error on {file_path}: "
                f"{result.stderr[:200]}"
            )
            return []

        # ── Handle empty output ──
        stdout = result.stdout.strip()
        if not stdout:
            logger.warning(
                f"Semgrep returned empty output for {file_path}"
            )
            return []

        # ── Parse JSON ──
        try:
            output = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to parse Semgrep JSON: {e}"
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
                    f"Skipping malformed Semgrep issue: {e}"
                )
                continue

        logger.debug(
            f"Semgrep found {len(findings)} "
            f"issues in {file_path}"
        )
        return findings

    def _parse_issue(
        self,
        issue: dict,
        file_path: str
    ) -> Finding:
        """
        Convert a single Semgrep JSON result entry
        into a Finding object.

        Args:
            issue:     One entry from Semgrep's results[].
            file_path: Original file path scanned.

        Returns:
            Finding: Populated Finding object.
        """
        extra    = issue.get("extra", {})
        metadata = extra.get("metadata", {})

        # ── Map severity ──
        raw_severity = extra.get("severity", "WARNING")
        severity = SEMGREP_SEVERITY_MAP.get(
            raw_severity.upper(), "MEDIUM"
        )

        # ── Get confidence from metadata ──
        raw_confidence = metadata.get(
            "confidence", "MEDIUM"
        ).upper()
        confidence = (
            raw_confidence
            if raw_confidence in VALID_CONFIDENCE
            else "MEDIUM"
        )

        # ── Extract vulnerability type from CWE ──
        cwe_list = metadata.get("cwe", [])
        vuln_type = DEFAULT_VULN_TYPE

        if cwe_list:
            # cwe_list is like ["CWE-89: Improper..."]
            # Take the first CWE and extract number
            first_cwe = cwe_list[0] if isinstance(
                cwe_list, list
            ) else cwe_list

            cwe_number = extract_cwe_number(str(first_cwe))
            vuln_type = CWE_TO_VULN_TYPE.get(
                cwe_number,
                DEFAULT_VULN_TYPE
            )

        # ── Get line number ──
        line_number = issue.get(
            "start", {}
        ).get("line", 0)

        # ── Get check_id for raw output ──
        check_id = issue.get("check_id", "")

        return Finding(
            tool_name=self.get_name(),
            file_path=file_path,
            line_number=line_number,
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            description=extra.get("message", ""),
            raw_output={
                "check_id":           check_id,
                "cwe":                cwe_list,
                "owasp":              metadata.get("owasp", []),
                "vulnerability_class": metadata.get(
                    "vulnerability_class", []
                ),
                "engine_kind":        extra.get(
                    "engine_kind", ""
                ),
            }
        )