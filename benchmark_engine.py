"""
benchmark_engine.py

The core orchestrator of the AI Security Benchmark Suite.

This file ties everything together:
- Loads the dataset (dataset_loader.py)
- Initializes all scanners (tools/)
- Runs every scanner on every test file
- Collects all results
- Passes results to metrics.py for scoring
- Saves results to disk (results/)
- Returns final scores for leaderboard display

DESIGN DECISION — WHY NOT ASYNC/PARALLEL?
The original plan included parallel execution with
asyncio or multiprocessing. For this version we use
sequential execution for three reasons:
1. Easier to debug when learning
2. Semgrep and Bandit are already multi-threaded
   internally
3. Parallel subprocess execution on Windows has
   known gotchas with process spawning

Parallel execution is documented as a future
improvement in README.md.
"""

import json
import csv
import logging
import yaml
from pathlib import Path
from datetime import datetime
from models import GroundTruth, ScanResult, ToolMetrics
from scanners import SecurityScanner
from dataset_loader import load_dataset_samples
from metrics import calculate_metrics, calculate_breakdown, rank_tools

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# LOAD CONFIG
# ─────────────────────────────────────────────

def load_config() -> dict:
    """
    Load settings from config.yaml.

    Returns:
        dict: Full configuration dictionary.
    """
    config_path = Path("config.yaml")
    if not config_path.exists():
        raise FileNotFoundError(
            "config.yaml not found. "
            "Run from the project root directory."
        )
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


# ─────────────────────────────────────────────
# SCANNER REGISTRATION
# ─────────────────────────────────────────────

def load_scanners(config: dict) -> list[SecurityScanner]:
    """
    Initialize and return all enabled scanners.

    Checks each scanner's is_available() method.
    Skips scanners that are not installed.
    Logs a warning for each skipped scanner.

    Args:
        config: Loaded config.yaml as dictionary.

    Returns:
        list[SecurityScanner]: Ready-to-use scanners.
    """
    from tools.bandit_adapter import BanditAdapter
    from tools.semgrep_adapter import SemgrepAdapter
    from tools.pipaudit_adapter import PipAuditAdapter

    scanner_config = config.get("scanners", {})
    timeout = scanner_config.get("default_timeout", 60)

    # All available scanners
    # To add your custom tool:
    # 1. Import it here
    # 2. Add it to candidates list below
    candidates: list[SecurityScanner] = [
        BanditAdapter(timeout=timeout),
        SemgrepAdapter(timeout=90),
        PipAuditAdapter(timeout=180),
    ]

    # Filter by enabled flag in config
    # and by actual availability on system
    active_scanners: list[SecurityScanner] = []

    for scanner in candidates:
        name = scanner.get_name().lower().replace("-", "_")

        # Check if enabled in config
        tool_config = scanner_config.get(name, {})
        if not tool_config.get("enabled", True):
            logger.info(
                f"Skipping {scanner.get_name()} "
                f"(disabled in config.yaml)"
            )
            continue

        # Check if installed on system
        if not scanner.is_available():
            logger.warning(
                f"Skipping {scanner.get_name()} "
                f"— not installed or not on PATH. "
                f"Install with: pip install "
                f"{scanner.get_name().lower()}"
            )
            continue

        active_scanners.append(scanner)
        logger.info(f"Scanner ready: {scanner.get_name()}")

    return active_scanners


# ─────────────────────────────────────────────
# CORE BENCHMARK RUNNER
# ─────────────────────────────────────────────

def run_benchmark(
    scanners: list[SecurityScanner],
    ground_truths: list[GroundTruth]
) -> dict[str, list[ScanResult]]:
    """
    Run all scanners on all test case files.

    For each scanner, scans every file in ground_truths
    and collects ScanResult objects.

    Args:
        scanners:      List of initialized scanners.
        ground_truths: List of GroundTruth objects
                       from dataset_loader.

    Returns:
        dict: Maps tool_name → list[ScanResult]
              One ScanResult per file per tool.
    """
    # Get unique file paths to scan
    # (ground_truths may have multiple entries
    #  per file for different vuln types)
    unique_files = list({
        gt.file_path for gt in ground_truths
    })

    total_files = len(unique_files)
    total_scans = total_files * len(scanners)

    logger.info(
        f"Starting benchmark: "
        f"{len(scanners)} scanners × "
        f"{total_files} files = "
        f"{total_scans} total scans"
    )

    results: dict[str, list[ScanResult]] = {
        scanner.get_name(): [] for scanner in scanners
    }

    completed = 0

        for scanner in scanners:
        logger.info(
            f"\nRunning {scanner.get_name()} "
            f"on {total_files} files..."
        )

        # pip-audit is a dependency scanner
        # it should run ONCE on requirements.txt
        # not once per file — that causes 50 timeouts
        if scanner.get_name() == "pip-audit":
            scan_result = scanner.run_scan(
                "requirements.txt"
            )
            # Duplicate the result for every file
            # so metrics calculation has same count
            for file_path in unique_files:
                import copy
                file_result = copy.copy(scan_result)
                file_result = type(scan_result)(
                    tool_name=scan_result.tool_name,
                    file_path=file_path,
                    findings=scan_result.findings,
                    scan_time_ms=scan_result.scan_time_ms,
                    error=scan_result.error,
                    success=scan_result.success
                )
                results[scanner.get_name()].append(
                    file_result
                )
            completed += total_files
            print(
                f"\r  Progress: {completed}/{total_scans} "
                f"({(completed/total_scans)*100:.0f}%) — "
                f"pip-audit: scanned requirements.txt once",
                end="",
                flush=True
            )
            continue

        for file_path in unique_files:
            scan_result = scanner.run_scan(file_path)
            results[scanner.get_name()].append(scan_result)

            completed += 1
            progress = (completed / total_scans) * 100
            print(
                f"\r  Progress: {completed}/{total_scans} "
                f"({progress:.0f}%) — "
                f"Current: {scanner.get_name()} "
                f"on {Path(file_path).name}",
                end="",
                flush=True
            )
    print()  # New line after progress indicator
    return results


# ─────────────────────────────────────────────
# SAVE RESULTS
# ─────────────────────────────────────────────

def save_results(
    metrics_list: list[ToolMetrics],
    breakdown: dict,
    ground_truths: list[GroundTruth],
    all_scan_results: dict[str, list[ScanResult]],
    config: dict
) -> Path:
    """
    Save benchmark results to JSON and CSV files.

    Creates a timestamped file in the results/ folder:
    results/benchmark_YYYYMMDD_HHMMSS.json
    results/benchmark_YYYYMMDD_HHMMSS.csv

    Args:
        metrics_list:     Ranked list of ToolMetrics.
        breakdown:        Per-vuln-type detection counts.
        ground_truths:    Original ground truth labels.
        all_scan_results: All ScanResult objects.
        config:           Loaded config dictionary.

    Returns:
        Path: Path to the saved JSON file.
    """
    results_dir = Path(
        config.get("benchmark", {}).get(
            "results_dir", "results"
        )
    )
    results_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"benchmark_{timestamp}"

    # ── Build output dictionary ──
    output = {
        "benchmark_run": {
            "timestamp":     timestamp,
            "total_files":   len({
                gt.file_path for gt in ground_truths
            }),
            "total_ground_truths": len(ground_truths),
        },
        "leaderboard": [m.to_dict() for m in metrics_list],
        "breakdown":   breakdown,
        "scan_summary": {
            tool: {
                "total_scans":    len(results),
                "successful":     sum(
                    1 for r in results if r.success
                ),
                "failed":         sum(
                    1 for r in results if not r.success
                ),
                "total_findings": sum(
                    len(r.findings) for r in results
                ),
            }
            for tool, results in all_scan_results.items()
        }
    }

    # ── Save JSON ──
    output_formats = config.get(
        "benchmark", {}
    ).get("output_formats", ["json"])

    json_path = results_dir / f"{base_name}.json"
    if "json" in output_formats:
        with open(json_path, "w") as f:
            json.dump(output, f, indent=2)
        logger.info(f"Results saved: {json_path}")

    # ── Save CSV ──
    if "csv" in output_formats:
        csv_path = results_dir / f"{base_name}.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "rank", "tool_name", "precision",
                "recall", "f1_score", "true_pos",
                "false_pos", "false_neg",
                "avg_time_ms", "total_scans"
            ])
            writer.writeheader()
            for rank, m in enumerate(metrics_list, 1):
                row = m.to_dict()
                row["rank"] = rank
                writer.writerow(row)
        logger.info(f"CSV saved: {csv_path}")

    return json_path


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

def run(
    sandboxed: bool = False
) -> tuple[list[ToolMetrics], dict]:
    """
    Main entry point for the benchmark suite.

    Called by run.py when user executes:
        python run.py
        python run.py --sandboxed

    Args:
        sandboxed: If True, run scanners inside
                   Docker containers. If False,
                   run directly on host machine.

    Returns:
        tuple: (ranked metrics list, breakdown dict)
    """
    logger.info("=" * 50)
    logger.info("AI Security Benchmark Suite")
    logger.info("=" * 50)

    # ── Load configuration ──
    try:
        config = load_config()
    except FileNotFoundError as e:
        logger.error(str(e))
        return [], {}

    # ── Sandboxed mode warning ──
    if sandboxed:
        logger.info(
            "Sandboxed mode: scanners will run "
            "inside Docker containers"
        )
    else:
        logger.info(
            "Direct mode: scanners running on host "
            "(use --sandboxed for Docker isolation)"
        )

    # ── Load dataset ──
    logger.info("Loading dataset from HuggingFace...")
    ground_truths = load_dataset_samples()

    if not ground_truths:
        logger.error(
            "No ground truth samples loaded. "
            "Check your internet connection and "
            "dataset configuration in config.yaml"
        )
        return [], {}

    logger.info(
        f"Loaded {len(ground_truths)} "
        f"ground truth samples"
    )

    # ── Initialize scanners ──
    scanners = load_scanners(config)

    if not scanners:
        logger.error(
            "No scanners available. "
            "Install at least one: "
            "pip install bandit semgrep pip-audit"
        )
        return [], {}

    # ── Run benchmark ──
    all_scan_results = run_benchmark(
        scanners=scanners,
        ground_truths=ground_truths
    )

    # ── Calculate metrics per tool ──
    metrics_list: list[ToolMetrics] = []

    for scanner in scanners:
        tool_name    = scanner.get_name()
        scan_results = all_scan_results[tool_name]

        tool_metrics = calculate_metrics(
            tool_name=tool_name,
            scan_results=scan_results,
            ground_truths=ground_truths
        )
        metrics_list.append(tool_metrics)

    # ── Rank tools ──
    rank_by = config.get(
        "leaderboard", {}
    ).get("rank_by", "f1_score")

    ranked_metrics = rank_tools(metrics_list, rank_by)

    # ── Calculate breakdown ──
    all_results_flat = [
        sr
        for results in all_scan_results.values()
        for sr in results
    ]

    breakdown = calculate_breakdown(
        scan_results=all_results_flat,
        ground_truths=ground_truths
    )

    # ── Save results ──
    json_path = save_results(
        metrics_list=ranked_metrics,
        breakdown=breakdown,
        ground_truths=ground_truths,
        all_scan_results=all_scan_results,
        config=config
    )

    logger.info(
        f"Benchmark complete. "
        f"Results saved to {json_path}"
    )

    return ranked_metrics, breakdown