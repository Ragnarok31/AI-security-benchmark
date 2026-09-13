"""
models.py

Core data structures for the AI Security Benchmark Suite.
Every piece of data that flows through this project —
findings from scanners, ground truth labels from the dataset,
and benchmark results — is defined here as a dataclass.

WHY DATACLASSES?
A dataclass automatically gives us:
- A clean __init__ method (no boilerplate)
- A readable __repr__ for debugging
- Type hints enforcement
- Easy conversion to dict for JSON export
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


# ─────────────────────────────────────────────
# ENUMS — Fixed vocabularies
# ─────────────────────────────────────────────

class Severity(str, Enum):
    """
    How dangerous is the vulnerability?
    We use str + Enum so it serializes to plain
    string in JSON automatically.
    HIGH   → exploitable with serious impact (SQLi, RCE)
    MEDIUM → exploitable with limited impact (XSS)
    LOW    → minor issue (weak but not broken crypto)
    """
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


class Confidence(str, Enum):
    """
    How sure is the scanner that this is a real vulnerability?
    HIGH   → almost certainly a real vulnerability
    MEDIUM → likely a vulnerability, needs review
    LOW    → possible false positive
    """
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


class VulnerabilityType(str, Enum):
    """
    The category of vulnerability found.
    Mapped to OWASP Top 10 categories.
    """
    SQL_INJECTION      = "SQL_INJECTION"
    XSS                = "XSS"
    HARDCODED_SECRET   = "HARDCODED_SECRET"
    WEAK_CRYPTO        = "WEAK_CRYPTO"
    COMMAND_INJECTION  = "COMMAND_INJECTION"
    PATH_TRAVERSAL     = "PATH_TRAVERSAL"
    INSECURE_DESERIAL  = "INSECURE_DESERIALIZATION"
    DEPENDENCY_CVE     = "DEPENDENCY_CVE"
    UNKNOWN            = "UNKNOWN"


# ─────────────────────────────────────────────
# FINDING — What a scanner reports
# ─────────────────────────────────────────────

@dataclass
class Finding:
    """
    A single vulnerability found by a security scanner.

    Every scanner adapter (Bandit, Semgrep, pip-audit)
    must return a list of Finding objects. This is the
    contract that makes all scanners interchangeable.

    Fields:
        tool_name        : Which scanner produced this
        file_path        : Path to the scanned file
        line_number      : Line where vulnerability exists
                           (0 if not applicable e.g. pip-audit)
        vulnerability_type: Category of vulnerability
        severity         : HIGH / MEDIUM / LOW
        confidence       : How sure the scanner is
        description      : Human readable explanation
        raw_output       : Original scanner output (for debugging)
    """
    tool_name:          str
    file_path:          str
    line_number:        int
    vulnerability_type: str
    severity:           str
    confidence:         str
    description:        str
    raw_output:         dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert Finding to dictionary for JSON export."""
        return asdict(self)


# ─────────────────────────────────────────────
# GROUND TRUTH — What we know to be true
# ─────────────────────────────────────────────

@dataclass
class GroundTruth:
    """
    The known correct answer for a test case.
    Loaded from the HuggingFace dataset metadata.

    This is what we compare scanner findings against
    to calculate True Positives, False Positives, etc.

    Fields:
        file_path        : Path to the vulnerable file
        line_number      : Line where vulnerability exists
                           (-1 means whole file is vulnerable)
        vulnerability_type: Category of vulnerability
        severity         : Expected severity level
        cve_id           : CVE identifier if available
        description      : Human readable description
    """
    file_path:          str
    vulnerability_type: str
    severity:           str
    line_number:        int = -1
    cve_id:             Optional[str] = None
    description:        str = ""

    def to_dict(self) -> dict:
        """Convert GroundTruth to dictionary for JSON export."""
        return asdict(self)


# ─────────────────────────────────────────────
# SCAN RESULT — One tool's result on one file
# ─────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    The complete output of running one scanner
    on one file.

    Fields:
        tool_name    : Name of the scanner
        file_path    : File that was scanned
        findings     : List of vulnerabilities found
        scan_time_ms : How long the scan took in milliseconds
        error        : Error message if scan failed
        success      : Whether the scan completed without error
    """
    tool_name:    str
    file_path:    str
    findings:     list[Finding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    error:        Optional[str] = None
    success:      bool = True

    def to_dict(self) -> dict:
        """Convert ScanResult to dictionary for JSON export."""
        return {
            "tool_name":    self.tool_name,
            "file_path":    self.file_path,
            "findings":     [f.to_dict() for f in self.findings],
            "scan_time_ms": self.scan_time_ms,
            "error":        self.error,
            "success":      self.success,
        }


# ─────────────────────────────────────────────
# BENCHMARK RESULT — Final scored output
# ─────────────────────────────────────────────

@dataclass
class ToolMetrics:
    """
    The final benchmark score for one tool
    across all test cases.

    Fields:
        tool_name   : Name of the scanner
        true_pos    : Vulnerabilities correctly found
        false_pos   : Safe code incorrectly flagged
        false_neg   : Vulnerabilities missed
        precision   : TP / (TP + FP) — trust score
        recall      : TP / (TP + FN) — coverage score
        f1_score    : Harmonic mean of precision + recall
        avg_time_ms : Average scan time in milliseconds
        total_scans : Number of files scanned
    """
    tool_name:   str
    true_pos:    int   = 0
    false_pos:   int   = 0
    false_neg:   int   = 0
    precision:   float = 0.0
    recall:      float = 0.0
    f1_score:    float = 0.0
    avg_time_ms: float = 0.0
    total_scans: int   = 0

    def to_dict(self) -> dict:
        """Convert ToolMetrics to dictionary for JSON export."""
        return asdict(self)