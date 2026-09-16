"""
dataset_loader.py

Downloads and prepares vulnerable Python code samples
from HuggingFace for use in the benchmark suite.

WHAT THIS FILE DOES:
1. Loads the HuggingFace dataset
2. Filters for samples with known CWE types
3. Saves each vulnerable code sample as a .py file
   in the appropriate test_cases/ subfolder
4. Returns a list of GroundTruth objects so the
   benchmark engine knows what each file contains

WHY SAVE FILES TO DISK?
Security scanners (Bandit, Semgrep) work on actual
files — they can't scan a Python string in memory.
We save each code sample as a real .py file, then
point the scanners at those files.
"""

import logging
import yaml
from pathlib import Path
from datasets import load_dataset
from models import GroundTruth

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CWE MAPPINGS
# Maps HuggingFace CWE codes to our internal
# VulnerabilityType strings (from models.py)
# and to subfolder names in test_cases/
# ─────────────────────────────────────────────

CWE_TO_VULN_TYPE = {
    "CWE-89":  "SQL_INJECTION",
    "CWE-79":  "XSS",
    "CWE-78":  "COMMAND_INJECTION",
    "CWE-77":  "COMMAND_INJECTION",
    "CWE-22":  "PATH_TRAVERSAL",
    "CWE-502": "INSECURE_DESERIALIZATION",
    "CWE-798": "HARDCODED_SECRET",
}

CWE_TO_SEVERITY = {
    "CWE-89":  "HIGH",
    "CWE-79":  "MEDIUM",
    "CWE-78":  "HIGH",
    "CWE-77":  "HIGH",
    "CWE-22":  "MEDIUM",
    "CWE-502": "HIGH",
    "CWE-798": "HIGH",
}

CWE_TO_FOLDER = {
    "CWE-89":  "sql_injection",
    "CWE-79":  "xss",
    "CWE-78":  "command_injection",
    "CWE-77":  "command_injection",
    "CWE-22":  "path_traversal",
    "CWE-502": "weak_crypto",
    "CWE-798": "hardcoded_secrets",
}

# CWEs we accept — anything else is skipped
VALID_CWES = set(CWE_TO_VULN_TYPE.keys())


# ─────────────────────────────────────────────
# LOAD CONFIG
# ─────────────────────────────────────────────

def load_config() -> dict:
    """
    Load settings from config.yaml.

    Returns:
        dict: Configuration values.

    Raises:
        FileNotFoundError: If config.yaml doesn't exist.
    """
    config_path = Path("config.yaml")
    if not config_path.exists():
        raise FileNotFoundError(
            "config.yaml not found. "
            "Are you running from the project root?"
        )
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


# ─────────────────────────────────────────────
# ENSURE FOLDERS EXIST
# ─────────────────────────────────────────────

def ensure_folders(base_dir: Path) -> None:
    """
    Create test_cases subfolders if they don't exist.
    Also creates two new folders we need for the
    expanded CWE types.

    Args:
        base_dir: Path to the test_cases directory.
    """
    folders = [
        "sql_injection",
        "xss",
        "hardcoded_secrets",
        "weak_crypto",
        "command_injection",
        "path_traversal",
    ]
    for folder in folders:
        folder_path = base_dir / folder
        folder_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Folder ready: {folder_path}")


# ─────────────────────────────────────────────
# SAVE CODE SAMPLE TO DISK
# ─────────────────────────────────────────────

def save_sample(
    code: str,
    folder: Path,
    sample_index: int
) -> Path:
    """
    Save a vulnerable code snippet as a .py file.

    File naming: sample_0001.py, sample_0002.py etc.
    Zero-padded so files sort correctly in any explorer.

    Args:
        code:         The vulnerable Python code string.
        folder:       The test_cases subfolder Path.
        sample_index: Index number for the filename.

    Returns:
        Path: The saved file's absolute path.
    """
    filename = f"sample_{sample_index:04d}.py"
    file_path = folder / filename

    # Only write if file doesn't already exist
    # This avoids re-downloading on every run
    if not file_path.exists():
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)
        logger.debug(f"Saved: {file_path}")
    else:
        logger.debug(f"Already exists, skipping: {file_path}")

    return file_path.resolve()


# ─────────────────────────────────────────────
# MAIN LOADER FUNCTION
# ─────────────────────────────────────────────

def load_dataset_samples() -> list[GroundTruth]:
    """
    Main entry point for the dataset loader.

    Downloads the HuggingFace dataset, filters for
    usable samples, saves them as .py files, and
    returns a list of GroundTruth objects.

    Returns:
        list[GroundTruth]: One entry per saved file.
                           Empty list if loading fails.
    """
    try:
        config = load_config()
    except FileNotFoundError as e:
        logger.error(str(e))
        return []

    dataset_name = config["dataset"]["name"]
    sample_size  = config["dataset"]["sample_size"]
    cache_dir    = Path(config["dataset"]["local_cache_dir"])

    logger.info(f"Loading dataset: {dataset_name}")
    logger.info(f"Sample limit: {sample_size}")

    # ── Download from HuggingFace ──
    try:
        ds = load_dataset(dataset_name, split="train")
        logger.info(f"Downloaded {len(ds)} total samples")
    except Exception as e:
        logger.error(f"Failed to load dataset: {e}")
        return []

    # ── Ensure subfolders exist ──
    ensure_folders(cache_dir)

    # ── Filter and process samples ──
    ground_truths: list[GroundTruth] = []
    saved_count = 0

    for sample in ds:
        # Stop when we hit the sample limit
        if saved_count >= sample_size:
            break

        # ── Extract metadata safely ──
        metadata = sample.get("metadata", {})
        if not isinstance(metadata, dict):
            continue

        cwe  = metadata.get("cwe", "CWE-UNKNOWN")
        code = sample.get("input", "").strip()

        # ── Skip unusable samples ──
        if cwe not in VALID_CWES:
            continue

        if not code:
            logger.warning(
                f"Empty code for CWE {cwe}, skipping"
            )
            continue

        # ── Map CWE to our types ──
        vuln_type = CWE_TO_VULN_TYPE[cwe]
        severity  = CWE_TO_SEVERITY[cwe]
        folder    = cache_dir / CWE_TO_FOLDER[cwe]

        # ── Get description safely ──
        # vulnerability_name and vulnerability_description
        # can both be None — we fall back gracefully
        vuln_name = metadata.get("vulnerability_name")
        vuln_desc = metadata.get("vulnerability_description")

        if vuln_name:
            description = vuln_name
        elif vuln_desc:
            description = vuln_desc[:100]
        else:
            description = f"{cwe} vulnerability"

        # ── Save file to disk ──
        try:
            file_path = save_sample(
                code=code,
                folder=folder,
                sample_index=saved_count + 1
            )
        except OSError as e:
            logger.error(f"Failed to save sample: {e}")
            continue

        # ── Create GroundTruth object ──
        # line_number is -1 because the dataset doesn't
        # tell us which specific line is vulnerable —
        # it marks the whole file as vulnerable.
        # Our metrics engine handles -1 by treating the
        # whole file as the vulnerability location.
        ground_truth = GroundTruth(
            file_path=str(file_path),
            vulnerability_type=vuln_type,
            severity=severity,
            line_number=-1,
            cve_id=None,
            description=description
        )

        ground_truths.append(ground_truth)
        saved_count += 1

    logger.info(
        f"Dataset ready: {saved_count} samples "
        f"saved to {cache_dir}"
    )

    return ground_truths


# ─────────────────────────────────────────────
# QUICK STATS HELPER
# ─────────────────────────────────────────────

def print_dataset_stats(
    ground_truths: list[GroundTruth]
) -> None:
    """
    Print a summary of loaded samples to the terminal.
    Useful for verifying the dataset loaded correctly.

    Args:
        ground_truths: List returned by load_dataset_samples()
    """
    from collections import Counter

    if not ground_truths:
        print("No samples loaded.")
        return

    print(f"\n{'='*45}")
    print(f"  DATASET SUMMARY")
    print(f"{'='*45}")
    print(f"  Total samples: {len(ground_truths)}")
    print(f"\n  By vulnerability type:")

    counts = Counter(gt.vulnerability_type for gt in ground_truths)
    for vuln_type, count in sorted(counts.items()):
        bar = "█" * count
        print(f"    {vuln_type:<25} {count:>3}  {bar}")

    print(f"\n  By severity:")
    severity_counts = Counter(
        gt.severity for gt in ground_truths
    )
    for severity, count in sorted(severity_counts.items()):
        print(f"    {severity:<10} {count}")
    print(f"{'='*45}\n")


# ─────────────────────────────────────────────
# RUN DIRECTLY TO TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    ground_truths = load_dataset_samples()
    print_dataset_stats(ground_truths)