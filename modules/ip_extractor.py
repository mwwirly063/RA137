"""
IP extraction module for RA137.

Resolves subdomains to IP addresses using ``dnsx`` and ``httpx``,
then extracts and validates all discovered IPs.
"""

from pathlib import Path
from typing import Set

from utils.command import run_command
from utils.logger import get_logger
from utils.ip_utils import is_valid_ip, extract_ipv4_from_text, sorted_ip_list
from utils.ai_report import generate_ai_report

_log = get_logger("IP-EXTRACT")


def run_dnsx(subdomain_file: Path, dnsx_file: Path) -> None:
    """Run dnsx for DNS resolution."""
    _log.info("Running dnsx")

    cmd = [
        "dnsx",
        "-l", str(subdomain_file),
        "-resp",
        "-silent",
        "-o", str(dnsx_file),
    ]
    run_command(cmd)
    _log.info("dnsx completed")


def run_httpx(subdomain_file: Path, httpx_file: Path) -> None:
    """Run httpx for HTTP probing and IP extraction."""
    _log.info("Running httpx")

    cmd = [
        "httpxx",
        "-l", str(subdomain_file),
        "-ip",
        "-silent",
        "-o", str(httpx_file),
    ]
    run_command(cmd)
    _log.info("httpx completed")


def extract_ips(dnsx_file: Path, httpx_file: Path, pure_ip_file: Path) -> Set[str]:
    """
    Extract and validate IPs from dnsx and httpx output files.

    Writes the deduplicated, validated IP list to *pure_ip_file*.
    """
    _log.info("Extracting IP addresses")

    all_ips: Set[str] = set()

    for file_path in (dnsx_file, httpx_file):
        if not file_path.exists():
            continue
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        all_ips |= extract_ipv4_from_text(content)

    # Filter to only valid IPs before writing
    valid_ips = sorted_ip_list(all_ips)

    with open(pure_ip_file, "w", encoding="utf-8") as f:
        for ip in valid_ips:
            f.write(ip + "\n")

    _log.info(f"Saved {len(valid_ips)} unique valid IPs")
    return set(valid_ips)


def collect_ips(output_dir: Path, target: str = "") -> Set[str]:
    """
    Run DNS resolution tools and extract all IP addresses.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory (must contain ``subdomains.txt``).
    """
    output_dir = Path(output_dir)
    subdomain_file = output_dir / "subdomains.txt"

    if not subdomain_file.exists():
        _log.warning("subdomains.txt not found – skipping IP extraction")
        return set()

    dnsx_file = output_dir / "dns1.txt"
    httpx_file = output_dir / "dns2.txt"
    pure_ip_file = output_dir / "pure_ip.txt"

    _log.info("Starting IP collection")

    run_dnsx(subdomain_file, dnsx_file)
    run_httpx(subdomain_file, httpx_file)
    ips = extract_ips(dnsx_file, httpx_file, pure_ip_file)

    _log.info("IP collection completed")

    # --- AI report -------------------------------------------------------
    report_lines = [f"Total IPs extracted: {len(ips)}"]
    report_lines.extend(f"IP: {ip}" for ip in sorted(ips)[:100])
    if len(ips) > 100:
        report_lines.append(f"... and {len(ips) - 100} more IPs")
    generate_ai_report(
        module_name="IP Extraction",
        data="\n".join(report_lines),
        target=target,
    )

    return ips
