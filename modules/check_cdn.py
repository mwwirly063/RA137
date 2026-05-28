"""
CDN / Cloud / Hosting detection module for RA137.

Reads the IP list produced by ``ip_extractor`` (``pure_ip.txt``), checks
each IP against the auto-maintained CDN range list, categorises them as
CDN / Cloud / Hosting / Direct, and writes structured JSON output.

Outputs
-------
* ``outputs/cdn/cdn_analysis.json`` – full structured analysis
* ``ip.txt``  – non-CDN (direct) IPs only  *(legacy compat)*
"""

import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.cdn_utils import (
    CDN_SOURCES,
    check_ip_cdn,
    load_cdn_networks,
    update_cdn_ranges,
)
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ai_report import generate_ai_report

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Build a reverse lookup: CIDR-string -> provider name + category
_PROVIDER_MAP: Dict[str, dict] = {}


def _build_provider_map() -> None:
    """Populate the global ``_PROVIDER_MAP`` from CDN_SOURCES."""
    if _PROVIDER_MAP:
        return  # already built
    for name, src in CDN_SOURCES.items():
        category = src.get("category", "unknown")
        for cidr in src.get("fallback_static", []):
            _PROVIDER_MAP[cidr] = {"provider": name, "category": category}


def _identify_provider(
    matched_cidr: str,
) -> dict:
    """Return ``{provider, category}`` for a matched CIDR."""
    _build_provider_map()
    # Exact match first
    if matched_cidr in _PROVIDER_MAP:
        return _PROVIDER_MAP[matched_cidr]
    # Fuzzy: try to match by network address
    try:
        net = ipaddress.ip_network(matched_cidr, strict=False)
        net_str = str(net)
        if net_str in _PROVIDER_MAP:
            return _PROVIDER_MAP[net_str]
    except (ValueError, TypeError):
        pass
    return {"provider": "unknown", "category": "unknown"}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def filter_non_cdn_ips(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> Dict[str, list]:
    """
    Analyse IPs against CDN / Cloud / Hosting ranges.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory (contains ``pure_ip.txt``).
    logger : Logger, optional
        Module logger (created automatically if omitted).

    Returns
    -------
    dict
        ``{cdn_ips, cloud_ips, hosting_ips, direct_ips}``
    """
    if logger is None:
        logger = get_logger("CDN")

    config = get_config()
    logger.info("Starting CDN / Cloud / Hosting detection")

    # ------------------------------------------------------------------
    # 1. Ensure CDN ranges are available
    # ------------------------------------------------------------------
    cdn_file = config.paths.cdn_file
    if not cdn_file.exists():
        logger.info("CDN file missing – downloading fresh ranges")
        update_cdn_ranges(cdn_file, logger, max_workers=config.concurrency.max_cdn_workers)

    networks = load_cdn_networks(cdn_file, logger, auto_update=True)

    # ------------------------------------------------------------------
    # 2. Load IPs
    # ------------------------------------------------------------------
    pure_ip_file = Path(output_dir) / "pure_ip.txt"
    if not pure_ip_file.exists():
        logger.warning(f"pure_ip.txt not found in {output_dir} – skipping")
        return {"cdn_ips": [], "cloud_ips": [], "hosting_ips": [], "direct_ips": []}

    with open(pure_ip_file, "r", encoding="utf-8") as fh:
        ips: List[str] = [ln.strip() for ln in fh if ln.strip()]

    if not ips:
        logger.warning("No IPs found in pure_ip.txt")
        return {"cdn_ips": [], "cloud_ips": [], "hosting_ips": [], "direct_ips": []}

    logger.info(f"Checking {len(ips)} IPs against {len(networks)} networks")

    # ------------------------------------------------------------------
    # 3. Classify each IP
    # ------------------------------------------------------------------
    results: Dict[str, list] = {
        "cdn_ips": [],
        "cloud_ips": [],
        "hosting_ips": [],
        "direct_ips": [],
    }

    for idx, ip in enumerate(ips, 1):
        logger.progress(idx, len(ips), "CDN check ")

        matched_cidr = check_ip_cdn(ip, networks)

        if matched_cidr:
            info = _identify_provider(matched_cidr)
            entry = {
                "ip": ip,
                "cidr": matched_cidr,
                "provider": info["provider"],
            }
            category = info["category"]
            if category == "cdn":
                results["cdn_ips"].append(entry)
            elif category == "cloud":
                results["cloud_ips"].append(entry)
            else:
                results["hosting_ips"].append(entry)
        else:
            results["direct_ips"].append(ip)

    # ------------------------------------------------------------------
    # 4. Save structured JSON output
    # ------------------------------------------------------------------
    cdn_dir = Path(output_dir) / "cdn"
    cdn_dir.mkdir(parents=True, exist_ok=True)

    json_file = cdn_dir / "cdn_analysis.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    # Also save the legacy ip.txt (direct IPs only) for downstream compat
    legacy_ip_file = Path(output_dir) / "ip.txt"
    with open(legacy_ip_file, "w", encoding="utf-8") as fh:
        for ip in sorted(results["direct_ips"]):
            fh.write(ip + "\n")

    # ------------------------------------------------------------------
    # 5. Summary
    # ------------------------------------------------------------------
    logger.success(
        f"CDN analysis complete: "
        f"{len(results['direct_ips'])} direct, "
        f"{len(results['cdn_ips'])} CDN, "
        f"{len(results['cloud_ips'])} cloud, "
        f"{len(results['hosting_ips'])} hosting"
    )
    logger.info(f"Structured output → {json_file}")

    # --- AI report -------------------------------------------------------
    report_lines = []
    for category in ["cdn_ips", "cloud_ips", "hosting_ips"]:
        for entry in results[category]:
            report_lines.append(
                f"{entry['ip']} | {category[:-1]} | {entry['provider']} | {entry['cidr']}"
            )
    for ip in results["direct_ips"]:
        report_lines.append(f"{ip} | direct | - | -")
    generate_ai_report(
        module_name="CDN Analysis",
        data="\n".join(report_lines) if report_lines else "No IPs analyzed.",
        target=target,
    )

    return results
