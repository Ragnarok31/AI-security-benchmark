"""
run.py

Entry point for the AI Security Benchmark Suite.

USAGE:
    # Run full benchmark (all tools, all test cases)
    python run.py

    # Run in sandboxed mode (Docker containers)
    python run.py --sandboxed

    # Run only specific tool
    python run.py --tool bandit
    python run.py --tool semgrep
    python run.py --tool pip-audit

    # Run with custom sample size
    python run.py --samples 100

HOW IT WORKS:
1. Parses command line arguments
2. Calls benchmark_engine.run()
3. Receives ranked metrics + breakdown
4. Prints the leaderboard to terminal
5. Tells user where results are saved
"""

import argparse
import logging
import sys
import yaml
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from models import ToolMetrics

# Initialize Rich console for pretty terminal output
console = Console()

# Set up logging — only show WARNING and above
# in normal mode to keep output clean
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# ─────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "AI Security Benchmark Suite — "
            "Compare security scanners on "
            "vulnerable Python code"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py
  python run.py --sandboxed
  python run.py --tool bandit
  python run.py --samples 100
  python run.py --verbose
        """
    )

    parser.add_argument(
        "--sandboxed",
        action="store_true",
        default=False,
        help="Run scanners inside Docker containers"
    )

    parser.add_argument(
        "--tool",
        type=str,
        default=None,
        choices=["bandit", "semgrep", "pip-audit"],
        help="Run only one specific scanner"
    )

    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help="Override sample size from config.yaml"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Show detailed logging output"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
# LEADERBOARD DISPLAY
# ─────────────────────────────────────────────

def print_leaderboard(
    metrics_list: list[ToolMetrics],
    breakdown: dict
) -> None:
    """
    Print the benchmark leaderboard to terminal
    using Rich for clean formatting.

    Args:
        metrics_list: Ranked list of ToolMetrics.
        breakdown:    Per-vuln-type detection counts.
    """
    if not metrics_list:
        console.print(
            "[red]No results to display.[/red]"
        )
        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ── Header ──
    console.print()
    console.print(Panel(
        f"[bold cyan]AI CODE SECURITY BENCHMARK[/bold cyan]\n"
        f"[dim]Run: {timestamp}[/dim]",
        box=box.DOUBLE,
        expand=False
    ))
    console.print()

    # ── Main Leaderboard Table ──
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white",
        title="[bold]SCANNER LEADERBOARD[/bold]",
        title_style="bold cyan",
    )

    table.add_column("RANK",      style="bold yellow", width=6)
    table.add_column("TOOL",      style="bold white",  width=12)
    table.add_column("PRECISION", style="cyan",        width=10)
    table.add_column("RECALL",    style="green",       width=10)
    table.add_column("F1 SCORE",  style="bold green",  width=10)
    table.add_column("TP",        style="green",       width=6)
    table.add_column("FP",        style="red",         width=6)
    table.add_column("FN",        style="yellow",      width=6)
    table.add_column("AVG TIME",  style="dim",         width=10)

    # Medal emojis for top 3
    medals = {1: "🥇", 2: "🥈", 3: "🥉"}

    for rank, metrics in enumerate(metrics_list, 1):
        medal = medals.get(rank, f"  {rank}")

        # Color F1 score by performance level
        f1 = metrics.f1_score
        if f1 >= 0.80:
            f1_str = f"[bold green]{f1:.3f}[/bold green]"
        elif f1 >= 0.60:
            f1_str = f"[yellow]{f1:.3f}[/yellow]"
        else:
            f1_str = f"[red]{f1:.3f}[/red]"

        avg_time = metrics.avg_time_ms
        if avg_time >= 1000:
            time_str = f"{avg_time/1000:.1f}s"
        else:
            time_str = f"{avg_time:.0f}ms"

        table.add_row(
            str(medal),
            metrics.tool_name,
            f"{metrics.precision:.3f}",
            f"{metrics.recall:.3f}",
            f1_str,
            str(metrics.true_pos),
            str(metrics.false_pos),
            str(metrics.false_neg),
            time_str,
        )

    console.print(table)
    console.print()

    # ── Vulnerability Breakdown Table ──
    if breakdown:
        _print_breakdown(breakdown, metrics_list)


def _print_breakdown(
    breakdown: dict,
    metrics_list: list[ToolMetrics]
) -> None:
    """
    Print per-vulnerability-type detection table.

    Args:
        breakdown:    Dict from calculate_breakdown().
        metrics_list: Ranked metrics for tool order.
    """
    # Get all vulnerability types present
    all_vuln_types: set[str] = set()
    for tool_counts in breakdown.values():
        all_vuln_types.update(tool_counts.keys())

    if not all_vuln_types:
        return

    vuln_types = sorted(all_vuln_types)
    tool_names = [m.tool_name for m in metrics_list]

    breakdown_table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white",
        title="[bold]VULNERABILITY DETECTION BREAKDOWN[/bold]",
        title_style="bold cyan",
    )

    breakdown_table.add_column(
        "VULNERABILITY TYPE",
        style="bold white",
        width=28
    )

    for tool_name in tool_names:
        breakdown_table.add_column(
            tool_name,
            style="cyan",
            width=12
        )

    for vuln_type in vuln_types:
        row = [vuln_type]
        for tool_name in tool_names:
            count = breakdown.get(
                tool_name, {}
            ).get(vuln_type, 0)
            if count > 0:
                row.append(f"[green]✓ {count}[/green]")
            else:
                row.append("[red]✗[/red]")
        breakdown_table.add_row(*row)

    console.print(breakdown_table)
    console.print()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    """
    Main entry point. Parses args, runs benchmark,
    prints leaderboard.
    """
    args = parse_args()

    # ── Verbose mode ──
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger("benchmark_engine").setLevel(
            logging.INFO
        )

    # ── Override sample size if specified ──
    if args.samples:
        try:
            config_path = Path("config.yaml")
            with open(config_path) as f:
                config = yaml.safe_load(f)
            config["dataset"]["sample_size"] = args.samples
            with open(config_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            console.print(
                f"[dim]Sample size set to "
                f"{args.samples}[/dim]"
            )
        except Exception as e:
            console.print(
                f"[red]Failed to update sample size: "
                f"{e}[/red]"
            )

    # ── Print startup message ──
    console.print()
    console.print(
        "[bold cyan]Starting benchmark...[/bold cyan]"
    )

    if args.sandboxed:
        console.print(
            "[yellow]Sandboxed mode: "
            "scanners running in Docker[/yellow]"
        )

    if args.tool:
        console.print(
            f"[dim]Running single tool: "
            f"{args.tool}[/dim]"
        )

    console.print()

    # ── Run benchmark ──
    try:
        from benchmark_engine import run
        metrics_list, breakdown = run(
            sandboxed=args.sandboxed
        )
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Benchmark interrupted "
            "by user.[/yellow]"
        )
        sys.exit(0)
    except Exception as e:
        console.print(
            f"[red]Benchmark failed: {e}[/red]"
        )
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # ── Print leaderboard ──
    if metrics_list:
        print_leaderboard(metrics_list, breakdown)
        console.print(
            "[dim]Full results saved to results/ "
            "folder[/dim]"
        )
    else:
        console.print(
            "[red]No results generated. "
            "Run with --verbose for details.[/red]"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()