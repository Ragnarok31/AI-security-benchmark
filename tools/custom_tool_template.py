"""
tools/custom_tool_template.py

============================================================
TEMPLATE FOR ADDING YOUR OWN SECURITY SCANNER
============================================================

HOW TO ADD YOUR OWN TOOL IN 5 MINUTES:

Step 1: Copy this file
        Copy this file and rename it to your tool's name.
        Example: tools/my_scanner_adapter.py

Step 2: Rename the class
        Change "CustomToolTemplate" to your tool's name.
        Example: class MyScanner(SecurityScanner)

Step 3: Fill in get_name()
        Return your tool's display name.
        This appears in the leaderboard.

Step 4: Fill in is_available()
        Return True if your tool is installed.
        Usually: run "your-tool --version" and check
        the exit code is 0.

Step 5: Fill in scan()
        Run your tool on the file_path argument.
        Parse its output.
        Return a list of Finding objects.
        Return [] if nothing found or if scan fails.

Step 6: Register your tool
        Open config.yaml and add your tool under
        the "custom_tools" section (see config.yaml).

Step 7: Run the benchmark
        python run.py
        Your tool automatically appears in the
        leaderboard alongside Bandit and Semgrep.

============================================================
RULES YOUR TOOL MUST FOLLOW:
============================================================

1. NEVER use shell=True in subprocess calls.
   BAD:  subprocess.run("mytool file.py", shell=True)
   GOOD: subprocess.run(["mytool", str(file_path)], ...)

2. NEVER let exceptions escape scan().
   Catch all exceptions, log them, return [].
   One broken tool must not crash the benchmark.

3. ALWAYS return list[Finding].
   Even if your tool found nothing → return []
   Even if your tool crashed → return []

4. ALWAYS set a timeout on subprocess calls.
   Use self.timeout (inherited from SecurityScanner).

5. ALWAYS use pathlib.Path for file paths.
   Never concatenate strings to build paths.

============================================================
FINDING OBJECT REFERENCE:
============================================================

Every vulnerability you find must be returned as a
Finding object with these fields:

    Finding(
        tool_name          = self.get_name(),
        file_path          = file_path,
        line_number        = 42,       # 0 if unknown
        vulnerability_type = "SQL_INJECTION",
        severity           = "HIGH",   # HIGH/MEDIUM/LOW only
        confidence         = "MEDIUM", # HIGH/MEDIUM/LOW only
        description        = "Human readable explanation",
        raw_output         = {}        # your tool's raw JSON
    )

Valid vulnerability_type values:
    "SQL_INJECTION"
    "XSS"
    "COMMAND_INJECTION"
    "PATH_TRAVERSAL"
    "HARDCODED_SECRET"
    "INSECURE_DESERIALIZATION"
    "DEPENDENCY_CVE"
    "WEAK_CRYPTO"
    "UNKNOWN"

============================================================
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


class CustomToolTemplate(SecurityScanner):
    """
    Template scanner — copy and customize this class.

    Replace every TODO comment with your implementation.
    Delete these instructions once your tool works.
    """

    def get_name(self) -> str:
        """
        Return your tool's display name.
        This appears in the leaderboard and reports.

        TODO: Replace "CustomTool" with your tool's name.
        """
        return "CustomTool"  # TODO: change this

    def is_available(self) -> bool:
        """
        Return True if your tool is installed and
        accessible on the system PATH.

        This is called once before benchmarking starts.
        If it returns False, your tool is skipped with
        a clear warning in the output.

        TODO: Replace "your-tool" with your CLI command.
        """
        try:
            result = subprocess.run(
                ["your-tool", "--version"],  # TODO: change
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            # Tool not installed
            return False
        except subprocess.TimeoutExpired:
            return False

    def scan(self, file_path: str) -> list[Finding]:
        """
        Scan a single file for vulnerabilities.

        This method is called by the benchmark engine
        for every test case file. Return a list of
        Finding objects — one per vulnerability found.

        Args:
            file_path: Absolute path to the file to scan.

        Returns:
            list[Finding]: Vulnerabilities found.
                           Return [] if nothing found.
                           Return [] if scan fails.

        TODO: Implement your scanning logic below.
        """
        path = Path(file_path)

        # ── Validate file exists ──
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        # ── Run your tool as subprocess ──
        # TODO: Replace with your tool's actual command.
        # NEVER use shell=True.
        # Always pass arguments as a list.
        # Always set timeout=self.timeout.
        try:
            result = subprocess.run(
                [
                    "your-tool",        # TODO: change
                    "--output", "json", # TODO: change
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            raise ScanTimeoutError(
                f"your-tool timed out after "
                f"{self.timeout}s on {file_path}"
            )
        except FileNotFoundError:
            raise ToolNotAvailableError(
                "your-tool not found. "
                "Install it with: pip install your-tool"
            )

        # ── Check for errors ──
        # TODO: Adjust exit codes for your tool.
        # Common patterns:
        #   0 = success (no findings)
        #   1 = success (findings found)
        #   2+ = error
        if result.returncode > 1:
            logger.error(
                f"your-tool error: {result.stderr[:200]}"
            )
            return []

        # ── Parse output ──
        # TODO: Parse your tool's output format.
        # If JSON:
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse output: {e}")
            return []

        # ── Convert to Finding objects ──
        findings: list[Finding] = []

        # TODO: Replace with your tool's actual JSON
        # structure. Look at what your tool outputs
        # and map each field to the Finding fields.
        for issue in output.get("results", []):
            try:
                finding = Finding(
                    tool_name=self.get_name(),
                    file_path=file_path,

                    # TODO: replace with your field name
                    line_number=issue.get("line", 0),

                    # TODO: map your tool's vuln types
                    # to our standard types
                    vulnerability_type=issue.get(
                        "type", "UNKNOWN"
                    ),

                    # TODO: must be HIGH, MEDIUM, or LOW
                    severity=issue.get(
                        "severity", "MEDIUM"
                    ).upper(),

                    # TODO: must be HIGH, MEDIUM, or LOW
                    confidence=issue.get(
                        "confidence", "MEDIUM"
                    ).upper(),

                    # TODO: human readable description
                    description=issue.get("message", ""),

                    # TODO: store your tool's raw output
                    # for debugging and transparency
                    raw_output=issue,
                )
                findings.append(finding)

            except (KeyError, ValueError) as e:
                logger.warning(
                    f"Skipping malformed issue: {e}"
                )
                continue

        return findings


# ============================================================
# REAL WORLD EXAMPLES
# ============================================================
#
# EXAMPLE 1: Tool that outputs plain text (not JSON)
# ─────────────────────────────────────────────────
# result = subprocess.run(["mytool", str(path)],
#                         capture_output=True, text=True,
#                         timeout=self.timeout)
# for line in result.stdout.splitlines():
#     parts = line.split(":")
#     if len(parts) >= 3:
#         findings.append(Finding(
#             tool_name=self.get_name(),
#             file_path=file_path,
#             line_number=int(parts[0]),
#             vulnerability_type="UNKNOWN",
#             severity="MEDIUM",
#             confidence="LOW",
#             description=parts[2].strip(),
#             raw_output={"raw_line": line}
#         ))
#
# EXAMPLE 2: Tool that outputs SARIF format
# ─────────────────────────────────────────
# SARIF is a standard format many tools use.
# output = json.loads(result.stdout)
# for run in output.get("runs", []):
#     for result in run.get("results", []):
#         location = result["locations"][0]
#         findings.append(Finding(
#             tool_name=self.get_name(),
#             file_path=file_path,
#             line_number=location["physicalLocation"]
#                         ["region"]["startLine"],
#             vulnerability_type="UNKNOWN",
#             severity="MEDIUM",
#             confidence="MEDIUM",
#             description=result["message"]["text"],
#             raw_output=result
#         ))
# ============================================================