"""
scanners.py

Abstract base class for all security scanner adapters.

WHY AN ABSTRACT BASE CLASS?
Every scanner (Bandit, Semgrep, pip-audit, custom tools)
works differently internally — different commands, different
output formats, different JSON structures. But the benchmark
engine needs to treat them all identically.

The solution: force every scanner to implement the same
three methods. Python's ABC (Abstract Base Class) module
makes this a hard requirement — if a scanner doesn't
implement all three methods, Python raises an error
immediately when you try to use it.

This pattern is called the "Strategy Pattern" in software
design. The benchmark engine is the context, each scanner
adapter is a strategy.
"""

from abc import ABC, abstractmethod
from models import Finding, ScanResult
import time
import logging

# Set up logging for this module
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)


# ─────────────────────────────────────────────
# CUSTOM EXCEPTIONS
# ─────────────────────────────────────────────

class ToolNotAvailableError(Exception):
    """
    Raised when a scanner tool is not installed
    or cannot be found on the system PATH.

    WHY A CUSTOM EXCEPTION?
    If we used a generic Exception, the benchmark engine
    couldn't distinguish between "tool not installed" and
    "tool crashed while scanning". Custom exceptions let
    us handle each case differently and give the user
    a clear, actionable error message.
    """
    pass


class ScanTimeoutError(Exception):
    """
    Raised when a scanner takes longer than the
    configured timeout to complete.

    WHY TIMEOUTS?
    Semgrep with complex rules on large files can hang.
    Without a timeout, one bad scan would freeze the
    entire benchmark run forever.
    """
    pass


# ─────────────────────────────────────────────
# ABSTRACT BASE CLASS
# ─────────────────────────────────────────────

class SecurityScanner(ABC):
    """
    Abstract base class that every scanner adapter
    must inherit from and implement.

    HOW TO USE THIS:
    1. Create a new file in /tools/
    2. Import SecurityScanner:
       from scanners import SecurityScanner
    3. Create a class that inherits from it:
       class MyScanner(SecurityScanner):
    4. Implement all three abstract methods
    5. Your scanner automatically works with the
       benchmark engine

    If you skip implementing any abstract method,
    Python raises TypeError immediately — you cannot
    accidentally ship a broken scanner.
    """

    def __init__(self, timeout: int = 60):
        """
        Args:
            timeout: Maximum seconds a scan can run.
                     Default is 60 seconds.
        """
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def scan(self, file_path: str) -> list[Finding]:
        """
        Scan a single file for security vulnerabilities.

        The benchmark engine calls this method on every
        scanner and expects back a list of Finding objects.

        Args:
            file_path: Absolute path to the file to scan.

        Returns:
            list[Finding]: Every vulnerability found.
                           Empty list [] if nothing found.
                           Empty list [] if scan fails —
                           log the error, never raise.

        CRITICAL RULE:
            Never let exceptions escape this method.
            One broken scanner must not stop the others.
            Catch all exceptions, log them, return [].
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """
        Return the display name of this scanner.
        Used in leaderboard and reports.

        Returns:
            str: Short display name e.g. "Bandit"

        Example:
            def get_name(self) -> str:
                return "Bandit"
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check whether this scanner is installed
        and accessible on the system PATH.

        Called once before benchmarking starts.
        If this returns False, the scanner is skipped
        with a clear warning — benchmark continues
        with remaining tools.

        Returns:
            bool: True if tool is ready to use.
                  False if tool is not installed.

        Example:
            def is_available(self) -> bool:
                result = subprocess.run(
                    ["bandit", "--version"],
                    capture_output=True
                )
                return result.returncode == 0
        """
        pass

    # ─────────────────────────────────────────
    # CONCRETE METHOD — already implemented
    # Subclasses inherit this for free
    # ─────────────────────────────────────────

    def run_scan(self, file_path: str) -> ScanResult:
        """
        Wrapper around scan() that handles timing,
        error catching, and ScanResult construction.

        The benchmark engine calls run_scan() not scan()
        directly. This ensures timing and error handling
        are consistent across ALL scanners automatically —
        individual adapters only need to implement scan().

        Args:
            file_path: Absolute path to the file to scan.

        Returns:
            ScanResult: Complete result including findings,
                        timing, and error information.
        """
        start_time = time.monotonic()

        try:
            # Check tool is available before scanning
            if not self.is_available():
                raise ToolNotAvailableError(
                    f"{self.get_name()} is not installed "
                    f"or not found on PATH."
                )

            # Run the actual scan
            findings = self.scan(file_path)

            # Calculate time taken
            elapsed_ms = (time.monotonic() - start_time) * 1000

            self.logger.info(
                f"{self.get_name()} scanned {file_path} "
                f"— {len(findings)} finding(s) "
                f"in {elapsed_ms:.1f}ms"
            )

            return ScanResult(
                tool_name=self.get_name(),
                file_path=file_path,
                findings=findings,
                scan_time_ms=elapsed_ms,
                success=True
            )

        except ToolNotAvailableError as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self.logger.error(f"Tool not available: {e}")
            return ScanResult(
                tool_name=self.get_name(),
                file_path=file_path,
                findings=[],
                scan_time_ms=elapsed_ms,
                error=str(e),
                success=False
            )

        except ScanTimeoutError as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self.logger.error(
                f"{self.get_name()} timed out "
                f"after {self.timeout}s on {file_path}"
            )
            return ScanResult(
                tool_name=self.get_name(),
                file_path=file_path,
                findings=[],
                scan_time_ms=elapsed_ms,
                error=str(e),
                success=False
            )

        except Exception as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self.logger.error(
                f"{self.get_name()} unexpected error "
                f"on {file_path}: {e}"
            )
            return ScanResult(
                tool_name=self.get_name(),
                file_path=file_path,
                findings=[],
                scan_time_ms=elapsed_ms,
                error=str(e),
                success=False
            )