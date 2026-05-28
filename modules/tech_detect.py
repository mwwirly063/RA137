"""
Technology detection module for RA137.

Runs technology fingerprinting against ``final_ip.txt`` using:
    * **httpx** – HTTP probing with tech-detect, title, server headers
    * **gow** (gowitness) – full-page screenshots

All results are stored in a single unified output file (no separation into
WAF / IIS / default-page buckets).

Outputs
-------
* ``outputs/tech/tech_results.json``  – structured results
* ``outputs/tech/httpx_raw.txt``       – raw httpx output
* ``<target>/pure_httpx.txt``          – legacy per-target copy
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from utils.command import run_command
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ai_report import generate_ai_report

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WAF_KEYWORDS = [
    "cloudflare", "akamai", "imperva", "incapsula",
    "sucuri", "f5", "fastly", "aws", "edge",
]

IIS_DEFAULT_KEYWORDS = [
    "iis windows server",
    "welcome to iis",
    "internet information services",
]

OTHER_DEFAULT_KEYWORDS = [
    "apache2 ubuntu default page",
    "nginx welcome",
    "test page",
    "default page",
    "placeholder page",
    "it works",
    "welcome page",
]

PORTS = "80,443,4443,7443,8443,9443,10443"


# ---------------------------------------------------------------------------
# httpx runner
# ---------------------------------------------------------------------------

def _run_httpx(ip_file: Path, output_file: Path, logger: Logger) -> None:
    """Run httpx tech detection against the given IP file."""
    logger.info(f"Running httpx tech detection on {ip_file}")

    cmd = [
        "httpxx",
        "-l", str(ip_file),
        "-ports", PORTS,
        "-title",
        "-server",
        "-tech-detect",
        "-silent",
        "-o", str(output_file),
    ]

    result = run_command(cmd)
    if not result.success:
        logger.warning(f"httpx exited with code {result.returncode}: {result.stderr[:200]}")
    else:
        logger.info("httpx tech detection completed")


# ---------------------------------------------------------------------------
# Result parser (unified – no category splitting)
# ---------------------------------------------------------------------------

def _parse_httpx_results(
    httpx_file: Path,
    logger: Logger,
) -> List[dict]:
    """
    Parse httpx output into a unified list of result dicts.

    Each entry contains the raw line plus any detected tags (WAF, IIS default, etc.).
    """
    results: List[dict] = []

    if not httpx_file.exists():
        logger.warning(f"httpx output not found: {httpx_file}")
        return results

    with open(httpx_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            tags: List[str] = []
            lower = line.lower()

            # Detect WAF
            for waf in WAF_KEYWORDS:
                if waf in lower:
                    tags.append(f"waf:{waf}")

            # Detect IIS default pages
            for kw in IIS_DEFAULT_KEYWORDS:
                if kw in lower:
                    tags.append("default:iis")
                    break

            # Detect other default pages
            for kw in OTHER_DEFAULT_KEYWORDS:
                if kw in lower:
                    tags.append("default:other")
                    break

            # Extract URL (first field before brackets)
            url = line.split(" [")[0].split(" ")[0].strip()

            results.append({
                "raw": line,
                "url": url,
                "tags": tags,
            })

    logger.info(f"Parsed {len(results)} httpx results")
    waf_count = sum(1 for r in results if any(t.startswith("waf:") for t in r["tags"]))
    default_count = sum(1 for r in results if any(t.startswith("default:") for t in r["tags"]))
    logger.info(f"  WAF detections: {waf_count}, Default pages: {default_count}")

    return results


# ---------------------------------------------------------------------------
# gow (gowitness) runner
# ---------------------------------------------------------------------------

def _run_gow(url_file: Path, output_dir: Path, logger: Logger) -> None:
    """Run gowitness screenshot scan on URLs."""
    if not url_file.exists():
        logger.warning("URL file not found for gow – skipping screenshots")
        return

    # Compute relative path from output_dir (gow runs with cwd=output_dir)
    rel_path = url_file.relative_to(output_dir)

    screenshot_dir = Path(output_dir) / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Running gow screenshot scan on {rel_path}")
    cmd = [
        "gow", "scan", "file",
        "-f", str(rel_path),
        "--screenshot-fullpage",
        "--screenshot-path", str(screenshot_dir),
        "--write-jsonl",
    ]
    result = run_command(cmd, cwd=output_dir)
    if not result.success:
        logger.warning(f"gow exited with code {result.returncode}")
    else:
        logger.info("gow screenshot scan completed")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def tech_detection(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[dict]:
    """
    Run technology detection against final_ip.txt.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional
        Module logger.

    Returns
    -------
    list[dict]
        Unified tech detection results.
    """
    if logger is None:
        logger = get_logger("TECH")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting tech detection")

    # --- determine IP file to scan ---------------------------------------
    # Prefer per-target final_ip.txt
    final_ip_file = Path(output_dir) / "final" / "final_ip.txt"
    if not final_ip_file.exists():
        final_ip_file = output_dir / "final_ip.txt"
    if not final_ip_file.exists():
        # Legacy fallback to ip.txt
        final_ip_file = output_dir / "ip.txt"

    if not final_ip_file.exists():
        logger.warning("No IP file found for tech detection – skipping")
        return []

    # --- create output directory ------------------------------------------
    tech_dir = Path(output_dir) / "tech"
    tech_dir.mkdir(parents=True, exist_ok=True)

    httpx_raw = tech_dir / "httpx_raw.txt"

    # --- run httpx --------------------------------------------------------
    _run_httpx(final_ip_file, httpx_raw, logger)

    # --- parse results (unified) -----------------------------------------
    results = _parse_httpx_results(httpx_raw, logger)

    # --- run gow screenshots on httpx output (discovered URLs with ports) ---
    gow_url_file = tech_dir / "gow_urls.txt"
    if results:
        with open(gow_url_file, "w", encoding="utf-8") as fh:
            for r in results:
                url = r.get("url", "")
                if url:
                    fh.write(url + "\n")
        logger.info(f"Generated {len(results)} URLs for gowitness from httpx output")
        _run_gow(gow_url_file, output_dir, logger)

    # --- save structured JSON output -------------------------------------
    json_file = tech_dir / "tech_results.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump({
            "total_results": len(results),
            "results": results,
        }, fh, indent=2)

    # Also save legacy per-target copy
    legacy_file = output_dir / "pure_httpx.txt"
    with open(legacy_file, "w", encoding="utf-8") as fh:
        for r in results:
            fh.write(r["raw"] + "\n")

    # --- AI report -------------------------------------------------------
    report_lines = [r["raw"] for r in results]
    generate_ai_report(
        module_name="Tech Detection",
        data="\n".join(report_lines),
        target=target,
    )

    logger.success(f"Tech detection: {len(results)} results → {json_file}")
    return results
