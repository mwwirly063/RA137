"""
Certificate discovery module for RA137.

Scans SSL/TLS certificates on IP addresses (including /24 CIDR expansion)
to discover domains related to the target via CN and SAN fields.

Improvements:
- Deduplicates overlapping /24 ranges to avoid scanning the same subnet twice
- Uses config for timeouts and concurrency limits
- Thread-safe file writes with a lock
"""

import ipaddress
import socket
import ssl
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from utils.config import get_config
from utils.logger import get_logger
from utils.ai_report import generate_ai_report

_log = get_logger("CERT")

PORTS = [443, 4443, 7443, 8443, 10443]

_write_lock = threading.Lock()


def get_cert_domains(ip: str, port: int, timeout: int) -> dict:
    """
    Connect to *ip*:*port* via TLS and extract certificate CN + SAN domains.
    """
    result = {
        "ip": ip,
        "port": port,
        "common_name": None,
        "san": [],
        "error": None,
    }

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=None) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            raise Exception("No certificate received")

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            result["common_name"] = cn
        except IndexError:
            pass

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result["san"] = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

    except Exception as exc:
        result["error"] = str(exc)

    return result


def is_related(domain: str, target: str) -> bool:
    """Return ``True`` if *domain* contains the target name."""
    if not domain:
        return False
    return target.lower() in domain.lower()


def _expand_unique_subnets(ips: Set[str]) -> Set[str]:
    """
    Expand IPs into /24 subnets, deduplicating overlapping ranges.

    Returns the set of all unique host IPs across all unique /24 subnets.
    """
    seen_subnets: Set[ipaddress.IPv4Network] = set()
    all_hosts: Set[str] = set()

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            continue

        # Always include the original IP
        all_hosts.add(ip_str)

        if ip.version != 4:
            continue

        # Get the /24 network for this IP
        network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        if network in seen_subnets:
            continue  # Already expanded this /24
        seen_subnets.add(network)

        # Expand all hosts in this /24
        for host in network.hosts():
            all_hosts.add(str(host))

    _log.info(
        f"Expanded {len(ips)} IPs into {len(seen_subnets)} unique /24 subnets "
        f"→ {len(all_hosts)} total hosts to scan"
    )
    return all_hosts


def _check_ip(ip: str, target: str, output_file: Path, timeout: int) -> None:
    """Check all SSL ports on an IP for target-related certificates."""
    for port in PORTS:
        result = get_cert_domains(ip, port, timeout)

        matched = False
        if is_related(result["common_name"], target):
            matched = True

        for san in result["san"]:
            if is_related(san, target):
                matched = True
                break

        if matched:
            line = (
                f"[MATCH] IP={ip} PORT={port} "
                f"CN={result['common_name']} SAN={','.join(result['san'])}"
            )
            _log.info(line)

            with _write_lock:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")


def cert_discovery(target: str, output_dir: Path) -> None:
    """
    Run certificate discovery on IPs from ``ip.txt``.

    Expands each IP to its /24 subnet (deduplicating overlapping ranges),
    then probes SSL ports on every host for certificates mentioning the target.

    Parameters
    ----------
    target : str
        Target domain to match against certificate CN/SAN.
    output_dir : Path
        Per-target output directory.
    """
    _log.info("Starting certificate discovery")

    config = get_config()
    output_dir = Path(output_dir)
    ip_file = output_dir / "ip.txt"
    output_file = output_dir / "cert_discovery.txt"

    if not ip_file.exists():
        _log.warning("ip.txt not found – skipping cert discovery")
        return

    # Load base IPs
    base_ips: Set[str] = set()
    with open(ip_file, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                base_ips.add(ip)

    if not base_ips:
        _log.warning("No IPs in ip.txt – skipping cert discovery")
        return

    # Expand with /24 deduplication
    all_ips = _expand_unique_subnets(base_ips)

    ssl_timeout = config.timeouts.ssl_connection
    max_workers = config.concurrency.cert_discovery_workers

    _log.info(f"Scanning {len(all_ips)} IPs across {len(PORTS)} ports with {max_workers} workers")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_check_ip, ip, target, output_file, ssl_timeout)
            for ip in all_ips
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                _log.debug(f"Cert check error: {exc}")

    _log.info("Certificate discovery completed")

    # --- AI report -------------------------------------------------------
    if output_file.exists():
        with open(output_file, "r", encoding="utf-8") as fh:
            report_data = fh.read()
        generate_ai_report(
            module_name="Certificate Discovery",
            data=report_data if report_data.strip() else "No certificate matches found.",
            target=target,
        )
