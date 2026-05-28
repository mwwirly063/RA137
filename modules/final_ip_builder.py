"""
Final IP aggregation module for RA137.

Collects ALL discovered IPs from every upstream discovery module,
deduplicates, validates, and writes ``outputs/final/final_ip.txt``.

Sources consumed:
    * ``outputs/cdn/cdn_analysis.json``      – direct (non-CDN) IPs
    * ``outputs/realip/realip_results.json`` – origin-IP discovery
    * ``outputs/realip/asn_results.json``  – ASN/IP-range recon
    * ``<target>/cert_discovery.txt``         – certificate-based discovery
    * ``<target>/pure_ip.txt``                – fallback baseline

Outputs
-------
* ``outputs/final/final_ip.txt``  – one validated IP per line
* ``outputs/final/final_ip.json`` – structured metadata (source counts)
"""

import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ip_utils import (
    is_valid_ip,
    extract_ips_from_text,
    load_ips_from_file,
    sorted_ip_list,
)
from utils.ai_report import generate_ai_report

# Re-export for use within this module
_is_valid_ip = is_valid_ip
_extract_ips_from_text = extract_ips_from_text


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------

def _load_cdn_direct_ips(output_dir: Path, logger: Logger) -> Set[str]:
    """Load direct (non-CDN) IPs from cdn_analysis.json."""
    cdn_json = Path(output_dir) / "cdn" / "cdn_analysis.json"
    ips: Set[str] = set()
    if not cdn_json.exists():
        logger.info("CDN analysis not found – skipping direct IPs")
        return ips
    try:
        with open(cdn_json, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for ip in data.get("direct_ips", []):
            if _is_valid_ip(ip):
                ips.add(ip)
        logger.info(f"CDN direct IPs: {len(ips)}")
    except Exception as exc:
        logger.warning(f"Failed to load CDN analysis: {exc}")
    return ips


def _load_realip_results(output_dir: Path, logger: Logger) -> Set[str]:
    """Load IPs from realip_results.json."""
    json_file = Path(output_dir) / "realip" / "realip_results.json"
    ips: Set[str] = set()
    if not json_file.exists():
        logger.info("Real IP results not found – skipping")
        return ips
    try:
        with open(json_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data:
            ip = entry.get("ip", "")
            if _is_valid_ip(ip):
                ips.add(ip)
        logger.info(f"Real IP discovery IPs: {len(ips)}")
    except Exception as exc:
        logger.warning(f"Failed to load realip results: {exc}")
    return ips


def _load_asn_results(output_dir: Path, logger: Logger) -> tuple:
    """Load matched IPs and CIDR ranges from asn_results.json.

    Returns
    -------
    (ips, cidr_ranges) : tuple[Set[str], Set[str]]
    """
    json_file = Path(output_dir) / "realip" / "asn_results.json"
    ips: Set[str] = set()
    cidr_ranges: Set[str] = set()
    if not json_file.exists():
        logger.info("ASN results not found – skipping")
        return ips, cidr_ranges
    try:
        with open(json_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data.get("matches", []):
            value = entry.get("ip", "")
            # CIDR range
            if "/" in value:
                try:
                    net = ipaddress.ip_network(value, strict=False)
                    cidr_ranges.add(str(net))
                except ValueError:
                    pass
            # Individual IP
            elif _is_valid_ip(value):
                ips.add(value)

        # Also load prefixes from asns[] section (covers old-format files)
        for asn_entry in data.get("asns", []):
            for prefix_str in asn_entry.get("prefixes", []):
                try:
                    net = ipaddress.ip_network(prefix_str, strict=False)
                    cidr_ranges.add(str(net))
                except ValueError:
                    pass

        logger.info(f"ASN recon IPs: {len(ips)}, CIDR ranges: {len(cidr_ranges)}")
    except Exception as exc:
        logger.warning(f"Failed to load ASN results: {exc}")
    return ips, cidr_ranges


def _load_cert_discovery_ips(output_dir: Path, logger: Logger) -> Set[str]:
    """Load IPs from cert_discovery.txt (per-target)."""
    cert_file = Path(output_dir) / "cert_discovery.txt"
    ips: Set[str] = set()
    if not cert_file.exists():
        logger.info("cert_discovery.txt not found – skipping")
        return ips
    try:
        with open(cert_file, "r", encoding="utf-8") as fh:
            content = fh.read()
        ips = _extract_ips_from_text(content)
        logger.info(f"Certificate discovery IPs: {len(ips)}")
    except Exception as exc:
        logger.warning(f"Failed to load cert discovery: {exc}")
    return ips


def _load_pure_ips(output_dir: Path, logger: Logger) -> Set[str]:
    """Load baseline IPs from pure_ip.txt (per-target)."""
    pure_file = Path(output_dir) / "pure_ip.txt"
    ips = load_ips_from_file(pure_file)
    if ips:
        logger.info(f"Baseline pure IPs: {len(ips)}")
    else:
        logger.info("pure_ip.txt not found or empty – skipping baseline")
    return ips


# _load_cidr_ranges is no longer needed – CIDR ranges are now loaded
# directly via _load_asn_results() as first-class entries.


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_final_ips(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[str]:
    """
    Aggregate all discovered IPs from every discovery module.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional
        Module logger.

    Returns
    -------
    list[str]
        Sorted, deduplicated list of validated IPs.
    """
    if logger is None:
        logger = get_logger("FINAL-IP")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting final IP aggregation")

    # --- collect from all sources ----------------------------------------
    source_counts: Dict[str, int] = {}

    cdn_ips = _load_cdn_direct_ips(output_dir, logger)
    source_counts["cdn_direct"] = len(cdn_ips)

    realip_ips = _load_realip_results(output_dir, logger)
    source_counts["realip_discovery"] = len(realip_ips)

    asn_ips, asn_cidr_ranges = _load_asn_results(output_dir, logger)
    source_counts["asn_recon"] = len(asn_ips)
    source_counts["asn_recon_cidr"] = len(asn_cidr_ranges)

    cert_ips = _load_cert_discovery_ips(output_dir, logger)
    source_counts["cert_discovery"] = len(cert_ips)

    pure_ips = _load_pure_ips(output_dir, logger)
    source_counts["pure_ip"] = len(pure_ips)

    # --- merge all -------------------------------------------------------
    all_ips = cdn_ips | realip_ips | asn_ips | cert_ips | pure_ips
    all_cidr_ranges = sorted(asn_cidr_ranges)

    logger.info(f"Total unique IPs before validation: {len(all_ips)}")

    # --- fallback: if absolutely nothing, use pure_ip.txt ----------------
    if not all_ips:
        logger.warning("No IPs from any discovery module")
        fallback_ips = load_ips_from_file(output_dir / "pure_ip.txt")
        if fallback_ips:
            logger.info("Falling back to pure_ip.txt")
            all_ips = fallback_ips
            source_counts["fallback_pure_ip"] = len(all_ips)

    if not all_ips:
        logger.warning("No IPs found from any source – final_ip.txt will be empty")

    # --- validate and sort -----------------------------------------------
    valid_ips: List[str] = []
    for ip in all_ips:
        if _is_valid_ip(ip):
            valid_ips.append(ip)
    
    valid_ips = sorted_ip_list(valid_ips)
    
    # --- expand CIDR ranges into individual IPs --------------------------
    MAX_CIDR_HOSTS = 1024  # /22 = 1022 hosts; skip larger ranges
    expanded_ips: Set[str] = set(valid_ips)

    # If no CIDR ranges found from ASN recon, generate /24 from direct IPs
    if not all_cidr_ranges and valid_ips:
        generated_cidrs: Set[str] = set()
        for ip_str in valid_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                # Build /24 network for this IP
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                generated_cidrs.add(str(network))
            except ValueError:
                pass
        if generated_cidrs:
            all_cidr_ranges = sorted(generated_cidrs)
            source_counts["generated_/24"] = len(all_cidr_ranges)
            logger.info(f"No ASN prefixes found – generated {len(all_cidr_ranges)} /24 ranges from direct IPs")

    for cidr in all_cidr_ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > MAX_CIDR_HOSTS:
                logger.warning(
                    f"CIDR {cidr} too large ({len(hosts)} hosts) – skipping expansion"
                )
                continue
            for host in hosts:
                expanded_ips.add(str(host))
            logger.info(f"Expanded {cidr} → {len(hosts)} IPs")
        except ValueError:
            logger.warning(f"Invalid CIDR range: {cidr}")
    
    # Re-sort after expansion
    final_ips = sorted_ip_list(list(expanded_ips))
    logger.info(f"Total IPs after CIDR expansion: {len(final_ips)}")
    
    # --- save outputs ----------------------------------------------------
    final_dir = Path(output_dir) / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
        
    # Plain text (all individual IPs, CIDRs already expanded)
    txt_file = final_dir / "final_ip.txt"
    with open(txt_file, "w", encoding="utf-8") as fh:
        for ip in final_ips:
            fh.write(ip + "\n")
        
    # JSON metadata
    json_file = final_dir / "final_ip.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump({
            "total_ips": len(final_ips),
            "total_cidr_ranges": len(all_cidr_ranges),
            "source_counts": source_counts,
            "ips": final_ips,
            "cidr_ranges": all_cidr_ranges,
        }, fh, indent=2)
        
    logger.success(
        f"Final IP aggregation: {len(final_ips)} unique IPs "
        f"(from {len(all_ips)} direct + {len(all_cidr_ranges)} CIDR ranges expanded) "
        f"→ {txt_file}"
    )
    for src, count in source_counts.items():
        if count:
            logger.info(f"  {src}: {count} IPs")

    # --- AI report -------------------------------------------------------
    report_lines = [f"Total IPs: {len(final_ips)}", f"CIDR ranges expanded: {len(all_cidr_ranges)}"]
    for src, count in source_counts.items():
        if count:
            report_lines.append(f"Source {src}: {count}")
    report_lines.append("---")
    report_lines.extend(f"IP: {ip}" for ip in final_ips[:100])
    if len(final_ips) > 100:
        report_lines.append(f"... and {len(final_ips) - 100} more IPs")
    generate_ai_report(
        module_name="Final IP Aggregation",
        data="\n".join(report_lines),
        target=target,
    )

    return final_ips
