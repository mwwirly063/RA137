"""
RA137 Reconnaissance Framework – Main execution entry point.

Execution flow:
    1. Subdomain enumeration        (subdomain_enum)
    2. IP extraction                (ip_extractor)
    3. CDN / Cloud / Hosting detect (check_cdn)
    4. Certificate discovery        (cert_discovery)
    5. Real IP discovery            (realip_discovery)
    6. ASN / IP-range recon       (asn_recon)
    7. Final IP aggregation         (final_ip_builder)
    8. Technology detection         (tech_detect)
    9. Network discovery            (network_discovery)
   10. Vulnerability checking       (vuln_check)
"""

import json
import os
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Optional, Set

from utils.logger import Logger, get_logger, set_default_log_file
from utils.database import init_db
from utils.paths import create_target_output
from utils.config import get_config
from utils.ai_report import generate_pdf_report
from utils.validate import validate_domain

from modules.subdomain_enum import collect_subdomains
from modules.ip_extractor import collect_ips
from modules.cert_discovery import cert_discovery
from modules.check_cdn import filter_non_cdn_ips
from modules.realip_discovery import real_ip_discovery
from modules.asn_recon import asn_recon
from modules.final_ip_builder import build_final_ips
from modules.tech_detect import tech_detection
from modules.network_discovery import network_discovery
from modules.vuln_check import nuclei_scan


# ---------------------------------------------------------------------------
# Execution steps – ordered
# ---------------------------------------------------------------------------
STEPS = [
    "subdomain_enum",
    "ip_extractor",
    "check_cdn",
    "cert_discovery",
    "realip_discovery",
    "asn_recon",
    "final_ip_builder",
    "tech_detection",
    "network_discovery",
    "vuln_check",
]


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event = threading.Event()


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    _shutdown_event.set()
    logger = get_logger("MAIN")
    logger.warning("Shutdown signal received – finishing current step and exiting...")


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# JSON-based step state tracker
# ---------------------------------------------------------------------------

def _state_file_path() -> Path:
    """Return the path to the step-completion state file."""
    config = get_config()
    return config.paths.output_base / ".step_state.json"


def _load_state() -> Dict[str, Dict[str, str]]:
    """
    Load step-completion state from JSON file.

    Structure: ``{target: {step: status}}`` where status is "done" or "failed".
    """
    path = _state_file_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(state: Dict) -> None:
    """Persist step-completion state to JSON file."""
    path = _state_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def _step_completed(state: Dict, target: str, step: str) -> bool:
    """Check whether a step has been successfully completed for a target.

    Also validates that the target's output directory still exists.
    If the output was deleted, the cached state is invalidated.
    """
    if state.get(target, {}).get(step) != "done":
        return False

    # Verify the target output directory still exists
    config = get_config()
    target_dir = config.paths.output_base / target
    if not target_dir.exists():
        # Output was deleted – invalidate all cached state for this target
        del state[target]
        _save_state(state)
        return False

    return True


def _mark_step(state: Dict, target: str, step: str, status: str) -> None:
    """Mark a step's status for a target ('done' or 'failed')."""
    if target not in state:
        state[target] = {}
    state[target][step] = status
    _save_state(state)


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------

def load_targets(logger: Logger) -> list:
    """Load and validate targets from the configured targets file."""
    config = get_config()
    targets_file = config.paths.targets_file

    if not targets_file.exists():
        logger.error(f"Targets file not found: {targets_file}")
        return []

    with open(targets_file, "r", encoding="utf-8") as fh:
        raw_targets = [line.strip() for line in fh if line.strip()]

    # Validate each target
    valid_targets = []
    for raw in raw_targets:
        domain = validate_domain(raw)
        if domain:
            valid_targets.append(domain)
        else:
            logger.error(f"Invalid target rejected: {raw!r}")

    return valid_targets


# ---------------------------------------------------------------------------
# Per-step runners
# ---------------------------------------------------------------------------

def _run_subdomain_enum(target: str, target_output: Path, logger: Logger) -> None:
    collect_subdomains(domain=target, wordlist_path="wordlists/subdomains.txt", output_dir=target_output, target=target)


def _run_ip_extractor(target: str, target_output: Path, logger: Logger) -> None:
    collect_ips(output_dir=target_output, target=target)


def _run_check_cdn(target: str, target_output: Path, logger: Logger) -> None:
    filter_non_cdn_ips(output_dir=target_output, logger=logger, target=target)


def _run_cert_discovery(target: str, target_output: Path, logger: Logger) -> None:
    cert_discovery(target=target, output_dir=target_output)


def _run_realip_discovery(target: str, target_output: Path, logger: Logger) -> None:
    real_ip_discovery(output_dir=target_output, logger=logger, target=target)


def _run_asn_recon(target: str, target_output: Path, logger: Logger) -> None:
    asn_recon(output_dir=target_output, target=target, logger=logger)


def _run_final_ip_builder(target: str, target_output: Path, logger: Logger) -> None:
    build_final_ips(output_dir=target_output, logger=logger, target=target)


def _run_tech_detection(target: str, target_output: Path, logger: Logger) -> None:
    tech_detection(output_dir=target_output, logger=logger, target=target)


def _run_network_discovery(target: str, target_output: Path, logger: Logger) -> None:
    network_discovery(output_dir=target_output, logger=logger, target=target)


def _run_vuln_check(target: str, target_output: Path, logger: Logger) -> None:
    nuclei_scan(output_dir=target_output, logger=logger, target=target)


# ---------------------------------------------------------------------------
# Step dispatcher
# ---------------------------------------------------------------------------

_STEP_RUNNERS = {
    "subdomain_enum":    _run_subdomain_enum,
    "ip_extractor":      _run_ip_extractor,
    "check_cdn":         _run_check_cdn,
    "cert_discovery":    _run_cert_discovery,
    "realip_discovery":  _run_realip_discovery,
    "asn_recon":         _run_asn_recon,
    "final_ip_builder":  _run_final_ip_builder,
    "tech_detection":    _run_tech_detection,
    "network_discovery": _run_network_discovery,
    "vuln_check":        _run_vuln_check,
}


def _execute_step(
    step: str,
    target: str,
    target_output: Path,
    logger: Logger,
    state: Dict,
) -> bool:
    """
    Execute a single step with error handling and completion tracking.

    Returns ``True`` if the step succeeded, ``False`` otherwise.
    Only marks the step as "done" on success.
    """
    if _step_completed(state, target, step):
        logger.info(f"Skipping {step} (already done)")
        return True

    runner = _STEP_RUNNERS.get(step)
    if runner is None:
        logger.error(f"Unknown step: {step}")
        return False

    logger.info(f"{'=' * 60}")
    logger.info(f"Running step: {step}")
    logger.info(f"{'=' * 60}")

    try:
        runner(target, target_output, logger)
        _mark_step(state, target, step, "done")
        logger.success(f"Step '{step}' completed")
        return True
    except Exception as exc:
        logger.error(f"Step '{step}' failed: {exc}")
        _mark_step(state, target, step, "failed")
        logger.warning(f"Continuing despite failure in {step}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _process_target(
    idx: int,
    target: str,
    total: int,
    config,
    state: Dict,
    state_lock: threading.Lock,
) -> bool:
    """Process a single target through the full pipeline.

    Thread-safe: uses a lock for state mutations and per-target log files.
    """
    target_output = create_target_output(target, config.paths.output_base)

    # Create per-target log file and switch the global default
    target_log_dir = target_output / "logs"
    target_log_dir.mkdir(parents=True, exist_ok=True)
    target_log_file = target_log_dir / "target.log"

    # Each thread gets its own logger pointing to the per-target log file
    target_logger = get_logger("MAIN", log_file=target_log_file)
    # Also set the global default for modules that create loggers internally
    set_default_log_file(target_log_file)

    target_logger.info(f"\n{'#' * 60}")
    target_logger.info(f"Target {idx}/{total}: {target}")
    target_logger.info(f"{'#' * 60}")

    for step in STEPS:
        if _shutdown_event.is_set():
            target_logger.warning("Shutdown requested – stopping step execution")
            break

        with state_lock:
            completed = _step_completed(state, target, step)

        if completed:
            target_logger.info(f"Skipping {step} (already done)")
            continue

        runner = _STEP_RUNNERS.get(step)
        if runner is None:
            target_logger.error(f"Unknown step: {step}")
            continue

        target_logger.info(f"{'=' * 60}")
        target_logger.info(f"Running step: {step}")
        target_logger.info(f"{'=' * 60}")

        try:
            runner(target, target_output, target_logger)
            with state_lock:
                _mark_step(state, target, step, "done")
            target_logger.success(f"Step '{step}' completed")
        except Exception as exc:
            target_logger.error(f"Step '{step}' failed: {exc}")
            with state_lock:
                _mark_step(state, target, step, "failed")
            target_logger.warning(f"Continuing despite failure in {step}")

    # --- generate PDF report from AI reports --------------------------
    if not _shutdown_event.is_set():
        try:
            generate_pdf_report(target, target_output)
        except Exception as exc:
            target_logger.warning(f"PDF report generation skipped: {exc}")

    target_logger.success(f"Finished target: {target}")
    return True


def main() -> None:
    """Run the full reconnaissance pipeline for all targets."""
    config = get_config()
    logger = get_logger("MAIN")

    logger.info("=" * 60)
    logger.info("RA137 Reconnaissance Framework – Starting")
    logger.info("=" * 60)

    # --- initialise database and output base directory ---------------------
    init_db()
    logger.info("Database initialized")

    config.paths.output_base.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output base ready: {config.paths.output_base}")

    # --- load targets -----------------------------------------------------
    targets = load_targets(logger)
    if not targets:
        logger.error("No valid targets found – exiting")
        return

    logger.info(f"{len(targets)} target(s) loaded: {', '.join(targets)}")

    # --- load persistent state -------------------------------------------
    state = _load_state()
    state_lock = threading.Lock()

    # --- parallelism setting (env: PARALLEL_TARGETS, default=1) ---------
    parallel_targets = int(os.environ.get("PARALLEL_TARGETS", "1"))
    if parallel_targets < 1:
        parallel_targets = 1

    logger.info(f"Processing {len(targets)} target(s) with {parallel_targets} worker(s)")

    # --- process targets -------------------------------------------------
    if parallel_targets == 1:
        # Sequential mode (default)
        for idx, target in enumerate(targets, 1):
            if _shutdown_event.is_set():
                logger.warning("Shutdown requested – skipping remaining targets")
                break

            logger.info(f"\n{'#' * 60}")
            logger.info(f"Target {idx}/{len(targets)}: {target}")
            logger.info(f"{'#' * 60}")

            target_output = create_target_output(target, config.paths.output_base)

            # Create per-target log file and switch the global default
            target_log_dir = target_output / "logs"
            target_log_dir.mkdir(parents=True, exist_ok=True)
            target_log_file = target_log_dir / "target.log"
            set_default_log_file(target_log_file)

            # Create a per-target logger that writes to both target and global log
            target_logger = get_logger("MAIN", log_file=target_log_file)

            for step in STEPS:
                if _shutdown_event.is_set():
                    logger.warning("Shutdown requested – stopping step execution")
                    break
                _execute_step(step, target, target_output, target_logger, state)

            # --- generate PDF report from AI reports --------------------------
            if not _shutdown_event.is_set():
                try:
                    generate_pdf_report(target, target_output)
                except Exception as exc:
                    target_logger.warning(f"PDF report generation skipped: {exc}")

            target_logger.success(f"Finished target: {target}")
    else:
        # Parallel mode
        with ThreadPoolExecutor(max_workers=parallel_targets) as pool:
            futures = {
                pool.submit(
                    _process_target, idx, target, len(targets), config, state, state_lock
                ): target
                for idx, target in enumerate(targets, 1)
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error(f"Target '{target}' failed: {exc}")

    # Reset global log file back to default after all targets
    set_default_log_file(config.paths.log_file)

    # --- final summary ----------------------------------------------------
    logger.info("=" * 60)
    if _shutdown_event.is_set():
        logger.warning("Framework exited early due to shutdown signal")
    else:
        logger.success("All targets completed")
    logger.summary()
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
