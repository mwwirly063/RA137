import ipaddress
import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from modules.realip_discovery import (
    load_cdn_ranges,
    is_cdn_ip,
)
from utils.ai_report import generate_ai_report
from utils.logger import log


RIPESTAT_BASE = "https://stat.ripe.net/data"

SSL_PORTS = [443, 8443]

SSL_TIMEOUT = 5

MAX_IPS_PER_PREFIX = 2048

MAX_WORKERS = 50

_api_cache = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ripestat(endpoint: str, resource: str):
    """Query RIPEstat API with caching."""

    cache_key = f"ripestat:{endpoint}:{resource}"

    if cache_key in _api_cache:
        log(f"RIPE cache hit: {cache_key}")
        return _api_cache[cache_key]

    try:

        url = f"{RIPESTAT_BASE}/{endpoint}/data.json"

        params = {"resource": resource}

        response = requests.get(
            url,
            params=params,
            timeout=20,
        )

        if response.status_code != 200:

            log(
                f"RIPEstat {endpoint} returned "
                f"{response.status_code} for {resource}"
            )

            return None

        data = response.json()

        result = data.get("data", {})

        _api_cache[cache_key] = result

        return result

    except Exception as e:

        log(f"RIPEstat {endpoint} error for {resource}: {e}")

        return None


def _get_ssl_domains(ip, port=443):
    """Get CN + SAN domains from an IP's SSL certificate."""

    result = set()

    try:

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (ip, port),
            timeout=SSL_TIMEOUT,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=None,
            ) as ssock:

                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            return result

        cert = x509.load_der_x509_certificate(
            der_cert,
            default_backend(),
        )

        try:

            cn = cert.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value

            result.add(cn.lower())

        except Exception as e:
            log(f"RIPE SSL CN error for {ip}:{port}: {e}")

        try:

            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            sans = san_ext.value.get_values_for_type(x509.DNSName)

            for san in sans:
                result.add(san.lower())

        except Exception as e:
            log(f"RIPE SSL SAN error for {ip}:{port}: {e}")

    except Exception as e:
        log(f"RIPE SSL error for {ip}:{port}: {e}")

    return result


def _is_related(domain, target):
    """Check if domain belongs to target (proper suffix match)."""

    if not domain:
        return False

    domain = domain.lower().rstrip(".")
    target = target.lower().rstrip(".")

    return (
        domain == target or
        domain.endswith("." + target)
    )


def _ip_matches_target(ip, target):
    """Check if an IP's SSL certificate matches the target domain."""

    for port in SSL_PORTS:

        domains = _get_ssl_domains(ip, port)

        for domain in domains:

            if _is_related(domain, target):
                return True, domain, port

    return False, None, None


# ---------------------------------------------------------------------------
# IP loading
# ---------------------------------------------------------------------------

def load_real_ips(output_dir):
    """Load real IPs from realip.txt (JSON lines)."""

    ips = set()

    realip_file = output_dir / "realip.txt"

    if not realip_file.exists():
        return ips

    with open(realip_file, "r") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:

                data = json.loads(line)

                ip = data.get("ip")

                if ip:
                    ips.add(ip)

            except Exception:

                import re

                found = re.findall(
                    r"(?:\d{1,3}\.){3}\d{1,3}",
                    line,
                )

                ips.update(found)

    log(f"Loaded {len(ips)} IPs from realip.txt")

    return ips


# ---------------------------------------------------------------------------
# RIPE queries
# ---------------------------------------------------------------------------

def query_network_info(ip):
    """
    Query RIPEstat network-info for an IP.

    Returns:
        dict with keys: asn, prefix, asns, prefixes
    """

    data = _ripestat("network-info", ip)

    if not data:
        return None

    asns = data.get("asns", [])
    prefix = data.get("prefix", "")

    # Get all announced prefixes for the primary ASN
    all_prefixes = set()

    if prefix:
        all_prefixes.add(prefix)

    for asn in asns:

        asn_prefixes = query_announced_prefixes(asn)

        all_prefixes.update(asn_prefixes)

    return {
        "asn": asns[0] if asns else None,
        "asns": asns,
        "prefix": prefix,
        "prefixes": sorted(all_prefixes),
    }


def query_announced_prefixes(asn):
    """Get all prefixes announced by an ASN."""

    if not asn:
        return set()

    data = _ripestat("announced-prefixes", asn)

    if not data:
        return set()

    prefixes = set()

    for entry in data.get("prefixes", []):

        prefix = entry.get("prefix")

        if prefix:
            prefixes.add(prefix)

    return prefixes


# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------

def expand_prefixes(prefixes, cdn_cidrs, known_ips, max_ips=MAX_IPS_PER_PREFIX):
    """
    Expand CIDR prefixes to individual IPs.

    Filters out:
    - CDN IPs
    - Already-known IPs
    """

    candidate_ips = set()

    for prefix_str in sorted(prefixes):

        try:

            network = ipaddress.ip_network(prefix_str, strict=False)

            hosts = list(network.hosts())

            if not hosts:
                continue

            # Cap expansion for very large prefixes (e.g. /8, /16)
            if len(hosts) > max_ips:

                log(
                    f"Prefix {prefix_str} has {len(hosts)} hosts, "
                    f"sampling first+last {max_ips // 2}"
                )

                half = max_ips // 2

                sampled = hosts[:half] + hosts[-half:]

            else:

                sampled = hosts

            for host in sampled:

                ip_str = str(host)

                # Skip if already known or CDN
                if ip_str in known_ips:
                    continue

                if is_cdn_ip(ip_str, cdn_cidrs):
                    continue

                candidate_ips.add(ip_str)

        except Exception as e:

            log(f"Prefix expansion error for {prefix_str}: {e}")

    log(f"Expanded {len(prefixes)} prefixes to {len(candidate_ips)} candidate IPs")

    return candidate_ips


# ---------------------------------------------------------------------------
# SSL validation (parallel)
# ---------------------------------------------------------------------------

def validate_ips_parallel(candidate_ips, target):
    """Check SSL certificates of candidate IPs in parallel."""

    matches = []

    ip_list = sorted(candidate_ips)

    log(f"Validating {len(ip_list)} candidate IPs via SSL")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = {
            executor.submit(_ip_matches_target, ip, target): ip
            for ip in ip_list
        }

        for future in as_completed(futures):

            ip = futures[future]

            try:

                matched, domain, port = future.result()

                if matched:

                    entry = {
                        "ip": ip,
                        "matched_domain": domain,
                        "port": port,
                    }

                    matches.append(entry)

                    log(
                        f"[RIPE MATCH] {ip}:{port} "
                        f"-> {domain} (target={target})"
                    )

            except Exception as e:

                log(f"RIPE validation error for {ip}: {e}")

    return matches


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def ripe_recon(target, output_dir):
    """
    Query RIPE to find additional IP ranges belonging to the target.

    Uses real IPs found by realip_discovery to discover ASNs, then
    expands all announced prefixes and validates them via SSL.

    Args:
        target: the target domain (e.g. "wam.ae")
        output_dir: pathlib.Path to the target's output directory
    """

    log("Starting RIPE reconnaissance")

    # Load known real IPs
    known_ips = load_real_ips(output_dir)

    if not known_ips:

        log("No real IPs found, skipping RIPE recon")

        return

    # Load CDN ranges once
    cdn_cidrs = load_cdn_ranges()

    # Collect all network info and prefixes
    all_prefixes = set()

    asn_map = {}  # ip -> network info

    for ip in sorted(known_ips):

        info = query_network_info(ip)

        if not info:
            continue

        asn_map[ip] = info

        all_prefixes.update(info["prefixes"])

        log(
            f"IP {ip}: ASN={info['asn']} "
            f"prefixes={len(info['prefixes'])}"
        )

    if not all_prefixes:

        log("No RIPE prefixes found")

        return

    log(
        f"Found {len(all_prefixes)} unique prefixes "
        f"from {len(asn_map)} IPs"
    )

    # Expand prefixes to candidate IPs (excluding CDN and known)
    candidate_ips = expand_prefixes(
        all_prefixes,
        cdn_cidrs,
        known_ips,
    )

    if not candidate_ips:

        log("No new candidate IPs after filtering")

        # Save ASN/prefix metadata even if no new IPs
        _save_metadata(asn_map, output_dir)

        return

    # Validate candidates via SSL
    matches = validate_ips_parallel(candidate_ips, target)

    # Save results
    _save_results(matches, asn_map, output_dir)

    # AI report
    report_lines = []

    for m in matches:

        report_lines.append(
            f"{m['ip']}:{m['port']} -> {m['matched_domain']}"
        )

    for ip, info in asn_map.items():

        report_lines.append(
            f"Origin IP={ip} ASN={info['asn']} "
            f"prefixes={info['prefixes']}"
        )

    generate_ai_report(
        module_name="RIPE Recon",
        data="\n".join(report_lines),
    )

    log(
        f"RIPE recon completed: "
        f"{len(matches)} new IPs matched target"
    )


# ---------------------------------------------------------------------------
# Save helpers
# ---------------------------------------------------------------------------

def _save_metadata(asn_map, output_dir):
    """Save ASN/prefix metadata to file."""

    meta_file = output_dir / "ripe_asn_info.json"

    with open(meta_file, "w") as f:

        for ip, info in asn_map.items():

            entry = {
                "ip": ip,
                "asn": info["asn"],
                "asns": info["asns"],
                "prefix": info["prefix"],
                "prefixes": info["prefixes"],
            }

            f.write(json.dumps(entry) + "\n")

    log(f"Saved ASN metadata to {meta_file}")


def _save_results(matches, asn_map, output_dir):
    """Save RIPE recon results."""

    result_file = output_dir / "ripe_recon.txt"

    with open(result_file, "w") as f:

        # Write matched IPs
        for m in matches:

            line = (
                f"[RIPE-MATCH] "
                f"IP={m['ip']} "
                f"PORT={m['port']} "
                f"DOMAIN={m['matched_domain']}"
            )

            f.write(line + "\n")

        f.write("\n")

        # Write ASN/prefix info
        for ip, info in asn_map.items():

            line = (
                f"[ASN-INFO] "
                f"ORIGIN={ip} "
                f"ASN={info['asn']} "
                f"PREFIXES={','.join(info['prefixes'])}"
            )

            f.write(line + "\n")

    log(f"Saved {len(matches)} RIPE matches to {result_file}")

    # Also save ASN metadata
    _save_metadata(asn_map, output_dir)
