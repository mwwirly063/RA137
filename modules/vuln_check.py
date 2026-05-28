"""
Vulnerability checking module for RA137.

Runs **nuclei** against the aggregated IP list (``final_ip.txt``).

Improvements over the original:
    * Uses ``final_ip.txt`` as the primary IP source
    * Gracefully skips invalid IPs
    * Structured JSON output
    * Improved logging and error handling
    * Retry / timeout support via ``run_command``

Outputs
-------
* ``outputs/vulns/vuln_results.json``    – structured results
* ``outputs/vulns/nuclei_results.txt``   – raw nuclei output
* ``outputs/vulns/nuclei_results.json``  – nuclei's own JSON export
* ``<target>/nuclei_targets.txt``        – targets file fed to nuclei
"""

import ipaddress
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from utils.command import run_command
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ai_report import generate_ai_report
from utils.telegram_alert import send_nuclei_results_to_telegram
from utils.ip_utils import is_valid_ip, load_ips_from_file, sorted_ip_list

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Fallback ports used when network_discovery results are not available
DEFAULT_PORTS = [80, 443, 4443, 7443, 8443, 9443, 10443]


# ---------------------------------------------------------------------------
# IP loading
# ---------------------------------------------------------------------------


def collect_all_ips(output_dir: Path, logger: Logger) -> List[str]:
    """
    Collect IPs from final_ip.txt and legacy per-target files.

    Returns a sorted list of unique, valid IPs.
    """
    # Primary: per-target final_ip.txt
    final_ip_file = output_dir / "final" / "final_ip.txt"
    if not final_ip_file.exists():
        final_ip_file = output_dir / "final_ip.txt"

    all_ips: Set[str] = set()

    # Load from final_ip.txt
    if final_ip_file.exists():
        final_ips = load_ips_from_file(final_ip_file)
        logger.info(f"Loaded {len(final_ips)} IPs from final_ip.txt")
        all_ips.update(final_ips)
    else:
        # Fallback: collect from legacy files
        logger.info("final_ip.txt not found – collecting from legacy files")
        for fpath in [output_dir / "ip.txt", output_dir / "cert_discovery.txt"]:
            ips = load_ips_from_file(fpath)
            if ips:
                logger.info(f"  {fpath.name}: {len(ips)} IPs")
            all_ips.update(ips)
        # realip.txt is JSON-lines
        realip_ips = load_ips_from_file(output_dir / "realip.txt", json_lines=True, json_ip_key="ip")
        if realip_ips:
            logger.info(f"  realip.txt: {len(realip_ips)} IPs")
            all_ips.update(realip_ips)

    return sorted_ip_list(all_ips)


def load_open_ports(output_dir: Path, logger: Logger) -> Dict[str, Set[int]]:
    """
    Load IP-to-open-ports mapping from network_discovery results.

    Reads ``network/network_results.json`` and extracts open ports from
    nmap, Shodan, FOFA, and Censys sources.

    Returns
    -------
    dict[str, set[int]]
        Mapping of IP address -> set of open port numbers.
        Empty dict if no results are available.
    """
    net_json = Path(output_dir) / "network" / "network_results.json"
    ip_ports: Dict[str, Set[int]] = {}

    if not net_json.exists():
        logger.info("network_results.json not found – no open port data available")
        return ip_ports

    try:
        with open(net_json, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.warning(f"Failed to read network_results.json: {exc}")
        return ip_ports

    results = data.get("results", {})

    # --- nmap: parse host + port from findings ---
    for entry in results.get("nmap", []):
        host = entry.get("host", "").strip("()")
        port_info = entry.get("port_info", "")
        if not host or not is_valid_ip(host):
            continue
        # Extract port number from lines like "443/tcp  open  ssl/https"
        port_match = re.match(r"(\d+)/(?:tcp|udp)", port_info)
        if port_match:
            port = int(port_match.group(1))
            ip_ports.setdefault(host, set()).add(port)

    # --- Shodan: ports list per IP ---
    for entry in results.get("shodan", []):
        ip = entry.get("ip", "")
        if ip and is_valid_ip(ip):
            ports = entry.get("ports", [])
            if ports:
                ip_ports.setdefault(ip, set()).update(
                    p for p in ports if isinstance(p, int)
                )

    # --- FOFA: ports list per IP ---
    for entry in results.get("fofa", []):
        ip = entry.get("ip", "")
        if ip and is_valid_ip(ip):
            ports = entry.get("ports", [])
            if ports:
                ip_ports.setdefault(ip, set()).update(
                    int(p) for p in ports
                    if isinstance(p, (int, str)) and str(p).isdigit()
                )

    # --- Censys: services with port numbers ---
    for entry in results.get("censys", []):
        ip = entry.get("ip", "")
        if ip and is_valid_ip(ip):
            for svc in entry.get("services", []):
                port = svc.get("port")
                if isinstance(port, int):
                    ip_ports.setdefault(ip, set()).add(port)

    # Summary
    total_ports = sum(len(p) for p in ip_ports.values())
    if ip_ports:
        logger.info(
            f"Loaded {total_ports} open ports across {len(ip_ports)} IPs "
            f"from network discovery"
        )
    else:
        logger.info("No open ports found in network_results.json")

    return ip_ports


# ---------------------------------------------------------------------------
# Target building
# ---------------------------------------------------------------------------

def build_targets(
    ips: List[str],
    ip_ports: Optional[Dict[str, Set[int]]] = None,
) -> Tuple[List[str], str]:
    """Build URL targets from IPs and their open ports.

    If *ip_ports* is provided, each IP is scanned only on its discovered
    open ports.  IPs without discovered ports are skipped.

    If *ip_ports* is ``None`` or empty, falls back to ``DEFAULT_PORTS``.

    Returns
    -------
    (targets, mode) : tuple[list[str], str]
        ``mode`` is ``"discovered"`` or ``"fallback"``.
    """
    targets: Set[str] = set()

    if ip_ports:
        for ip in ips:
            ports = ip_ports.get(ip)
            if not ports:
                continue  # skip IPs with no discovered open ports
            for port in sorted(ports):
                if port == 80:
                    targets.add(f"http://{ip}")
                elif port == 443:
                    targets.add(f"https://{ip}")
                else:
                    targets.add(f"https://{ip}:{port}")
        if targets:
            return sorted(targets), "discovered"

    # Fallback to default ports
    for ip in ips:
        for port in DEFAULT_PORTS:
            if port == 80:
                targets.add(f"http://{ip}")
            elif port == 443:
                targets.add(f"https://{ip}")
            else:
                targets.add(f"https://{ip}:{port}")
    return sorted(targets), "fallback"


def save_targets(targets: List[str], output_dir: Path) -> Path:
    """Write targets to a file and return its path."""
    input_file = output_dir / "nuclei_targets.txt"
    with open(input_file, "w", encoding="utf-8") as fh:
        for target in targets:
            fh.write(target + "\n")
    return input_file


# ---------------------------------------------------------------------------
# Nuclei runner
# ---------------------------------------------------------------------------

def run_nuclei(input_file: Path, output_dir: Path, logger: Logger) -> Path:
    """Run nuclei scan and return the path to the text output file."""
    output_file = output_dir / "nuclei_results.txt"
    json_file = output_dir / "nuclei_results.json"

    cmd = [
        "nuclei",
        "-l", str(input_file),
        "-silent",
        "-o", str(output_file),
        "-json-export", str(json_file),
    ]

    logger.info("Running nuclei scan")
    config = get_config()
    result = run_command(cmd, timeout=config.timeouts.command_execution)

    if not result.success:
        logger.warning(f"nuclei exited with code {result.returncode}: {result.stderr[:200]}")
    else:
        logger.info("Nuclei scan completed")

    return output_file


# ---------------------------------------------------------------------------
# Result parser
# ---------------------------------------------------------------------------

def parse_nuclei_results(output_file: Path, logger: Logger) -> List[dict]:
    """Parse nuclei text output into structured findings."""
    findings: List[dict] = []
    if not output_file.exists():
        logger.warning(f"Nuclei output not found: {output_file}")
        return findings

    try:
        with open(output_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    findings.append({
                        "raw": line,
                        "template": _extract_template_id(line),
                    })
    except Exception as exc:
        logger.error(f"Failed to parse nuclei results: {exc}")

    return findings


def _extract_template_id(line: str) -> str:
    """Try to extract the nuclei template ID from a result line."""
    # Typical format: [template-id] [severity] [type] matched-at
    match = re.match(r"\[([^\]]+)\]", line)
    return match.group(1) if match else "unknown"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def nuclei_scan(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[dict]:
    """
    Run nuclei vulnerability scan against final_ip.txt.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional
        Module logger.

    Returns
    -------
    list[dict]
        Structured vulnerability findings.
    """
    if logger is None:
        logger = get_logger("VULN")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting vulnerability check")

    # --- collect IPs -----------------------------------------------------
    ips = collect_all_ips(output_dir, logger)
    if not ips:
        logger.warning("No IPs found – skipping vulnerability scan")
        return []

    logger.info(f"Scanning {len(ips)} IPs for vulnerabilities")

    # --- load open ports from network_discovery --------------------------
    ip_ports = load_open_ports(output_dir, logger)

    # --- build targets ---------------------------------------------------
    targets, mode = build_targets(ips, ip_ports if ip_ports else None)
    if mode == "discovered":
        ips_with_ports = sum(1 for ip in ips if ip in ip_ports)
        logger.info(
            f"Built {len(targets)} targets from discovered open ports "
            f"({ips_with_ports}/{len(ips)} IPs have open ports)"
        )
    else:
        logger.info(
            f"Built {len(targets)} targets using fallback port list "
            f"(no open ports from network_discovery)"
        )

    input_file = save_targets(targets, output_dir)

    # --- create vulns output dir -----------------------------------------
    vuln_dir = Path(output_dir) / "vulns"
    vuln_dir.mkdir(parents=True, exist_ok=True)

    # --- run nuclei ------------------------------------------------------
    output_file = run_nuclei(input_file, vuln_dir, logger)

    # --- parse results ---------------------------------------------------
    findings = parse_nuclei_results(output_file, logger)

    # --- save structured JSON output ------------------------------------
    json_file = vuln_dir / "vuln_results.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump({
            "total_ips_scanned": len(ips),
            "total_targets": len(targets),
            "total_findings": len(findings),
            "findings": findings,
        }, fh, indent=2)

    # --- AI report -------------------------------------------------------
    report_data = "\n".join(f["raw"] for f in findings)
    generate_ai_report(
        module_name="Nuclei Scan",
        data=report_data,
        target=target,
    )

    # --- Telegram alerts -------------------------------------------------
    nuclei_json = vuln_dir / "nuclei_results.json"
    if nuclei_json.exists():
        try:
            send_nuclei_results_to_telegram(vuln_dir)
        except Exception as exc:
            logger.warning(f"Telegram alert failed: {exc}")

    logger.success(
        f"Vulnerability scan: {len(findings)} findings from {len(ips)} IPs → {json_file}"
    )

    return findings
