"""
metrics.py

Calculates benchmark scores by comparing scanner
findings against ground truth labels.

CORE CONCEPT:
For each test case (vulnerable file), we know the
ground truth — what vulnerability type it contains.
We compare this against what each scanner found and
calculate True Positives, False Positives, False
Negatives, Precision, Recall, and F1 score.

MATCHING STRATEGY:
Since our dataset doesn't provide exact line numbers,
we match at the file + vulnerability_type level.
A True Positive = scanner found the correct
vulnerability type in the correct file.
"""

import logging
from collections import defaultdict
from models import Finding, GroundTruth, ToolMetrics, ScanResult

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# MATCHING HELPER
# ─────────────────────────────────────────────

def normalize_path(path: str) -> str:
    """
    Normalize file paths for comparison.

    Windows uses backslashes, Python uses forward
    slashes. We normalize to forward slashes so
    path comparisons work cross-platform.

    Args:
        path: File path string.

    Returns:
        str: Normalized path with forward slashes
             and lowercase.
    """
    return path.replace("\\", "/").lower().strip()


def findings_match(
    finding: Finding,
    ground_truth: GroundTruth
) -> bool:
    """
    Determine if a scanner finding matches a ground
    truth label.

    Matching rules:
    1. File paths must match (normalized)
    2. Vulnerability types must match exactly
       OR finding type is a subset of ground truth
       (e.g. COMMAND_INJECTION matches if ground
        truth is COMMAND_INJECTION)

    WHY NOT MATCH ON LINE NUMBER?
    Our dataset labels whole files as vulnerable
    (line_number = -1). We can't penalize scanners
    for finding the right vulnerability on the
    wrong line when we don't know the right line.

    Args:
        finding:      What the scanner found.
        ground_truth: What we know to be true.

    Returns:
        bool: True if this is a True Positive match.
    """
    # Normalize paths for comparison
    finding_path = normalize_path(finding.file_path)
    truth_path   = normalize_path(ground_truth.file_path)

    # Paths must match
    if finding_path != truth_path:
        return False

    # Vulnerability types must match
    if finding.vulnerability_type != ground_truth.vulnerability_type:
        return False

    return True


# ─────────────────────────────────────────────
# CORE METRICS CALCULATION
# ─────────────────────────────────────────────

def calculate_metrics(
    tool_name: str,
    scan_results: list[ScanResult],
    ground_truths: list[GroundTruth]
) -> ToolMetrics:
    """
    Calculate benchmark metrics for one tool across
    all test cases.

    Algorithm:
    For each ground truth:
        Check if any finding matches it
        If yes  → True Positive
        If no   → False Negative (tool missed it)

    For each finding:
        Check if it matches any ground truth
        If yes  → already counted as True Positive
        If no   → False Positive (tool wrong)

    Args:
        tool_name:    Display name of the scanner.
        scan_results: All ScanResult objects from
                      this tool's scans.
        ground_truths: All known vulnerabilities.

    Returns:
        ToolMetrics: Complete benchmark score.
    """
    # ── Flatten all findings from all scans ──
    all_findings: list[Finding] = []
    total_scan_time = 0.0
    successful_scans = 0

    for scan_result in scan_results:
        all_findings.extend(scan_result.findings)
        total_scan_time += scan_result.scan_time_ms
        if scan_result.success:
            successful_scans += 1

    logger.info(
        f"Calculating metrics for {tool_name}: "
        f"{len(all_findings)} findings vs "
        f"{len(ground_truths)} ground truths"
    )

    # ── Count True Positives and False Negatives ──
    true_positives  = 0
    false_negatives = 0

    # Track which findings have been matched
    # to avoid double-counting
    matched_finding_indices: set[int] = set()

    for gt in ground_truths:
        matched = False

        for i, finding in enumerate(all_findings):
            if findings_match(finding, gt):
                true_positives += 1
                matched_finding_indices.add(i)
                matched = True
                break  # One TP per ground truth

        if not matched:
            false_negatives += 1
            logger.debug(
                f"{tool_name} missed: "
                f"{gt.vulnerability_type} in "
                f"{gt.file_path}"
            )

    # ── Count False Positives ──
    # Any finding NOT matched to a ground truth
    false_positives = sum(
        1 for i in range(len(all_findings))
        if i not in matched_finding_indices
    )

    # ── Calculate Precision, Recall, F1 ──
    precision = _safe_divide(
        true_positives,
        true_positives + false_positives
    )

    recall = _safe_divide(
        true_positives,
        true_positives + false_negatives
    )

    f1_score = _safe_divide(
        2 * precision * recall,
        precision + recall
    )

    # ── Average scan time ──
    avg_time = (
        total_scan_time / len(scan_results)
        if scan_results else 0.0
    )

    metrics = ToolMetrics(
        tool_name=tool_name,
        true_pos=true_positives,
        false_pos=false_positives,
        false_neg=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1_score, 4),
        avg_time_ms=round(avg_time, 1),
        total_scans=len(scan_results)
    )

    logger.info(
        f"{tool_name} scores: "
        f"P={precision:.2f} "
        f"R={recall:.2f} "
        f"F1={f1_score:.2f}"
    )

    return metrics


# ─────────────────────────────────────────────
# BREAKDOWN BY VULNERABILITY TYPE
# ─────────────────────────────────────────────

def calculate_breakdown(
    scan_results: list[ScanResult],
    ground_truths: list[GroundTruth]
) -> dict[str, dict[str, int]]:
    """
    Calculate per-vulnerability-type detection counts
    for the leaderboard breakdown table.

    Returns a nested dict:
    {
        "Bandit": {
            "SQL_INJECTION": 8,
            "XSS": 3,
            ...
        },
        "Semgrep": { ... }
    }

    Args:
        scan_results:  All ScanResult objects from
                       all tools.
        ground_truths: All known vulnerabilities.

    Returns:
        dict: Tool name → vuln type → count detected.
    """
    # Group scan results by tool name
    results_by_tool: dict[str, list[ScanResult]] = (
        defaultdict(list)
    )
    for sr in scan_results:
        results_by_tool[sr.tool_name].append(sr)

    breakdown: dict[str, dict[str, int]] = {}

    for tool_name, tool_results in results_by_tool.items():
        tool_findings: list[Finding] = []
        for sr in tool_results:
            tool_findings.extend(sr.findings)

        vuln_counts: dict[str, int] = defaultdict(int)

        for gt in ground_truths:
            for finding in tool_findings:
                if findings_match(finding, gt):
                    vuln_counts[gt.vulnerability_type] += 1
                    break

        breakdown[tool_name] = dict(vuln_counts)

    return breakdown


# ─────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────

def _safe_divide(
    numerator: float,
    denominator: float
) -> float:
    """
    Divide two numbers safely.
    Returns 0.0 if denominator is zero to avoid
    ZeroDivisionError when a tool finds nothing.

    Args:
        numerator:   Top number.
        denominator: Bottom number.

    Returns:
        float: Result or 0.0 if denominator is zero.
    """
    if denominator == 0:
        return 0.0
    return numerator / denominator


def rank_tools(
    metrics_list: list[ToolMetrics],
    rank_by: str = "f1_score"
) -> list[ToolMetrics]:
    """
    Sort a list of ToolMetrics by the given metric,
    highest first.

    Args:
        metrics_list: List of ToolMetrics to rank.
        rank_by:      Field to sort by.
                      Options: f1_score, precision,
                               recall, avg_time_ms

    Returns:
        list[ToolMetrics]: Sorted list, best first.
    """
    valid_fields = {
        "f1_score", "precision", "recall", "avg_time_ms"
    }

    if rank_by not in valid_fields:
        logger.warning(
            f"Invalid rank_by field: {rank_by}. "
            f"Defaulting to f1_score."
        )
        rank_by = "f1_score"

    # For time, lower is better — reverse=False
    # For scores, higher is better — reverse=True
    reverse = rank_by != "avg_time_ms"

    return sorted(
        metrics_list,
        key=lambda m: getattr(m, rank_by),
        reverse=reverse
    )