"""
Shared IP address utilities for RA137.

Consolidates IP validation, regex extraction, and IPv6 support
into a single canonical module used by all discovery modules.
"""

import ipaddress
import re
from typing import Set


# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# IPv4: matches dotted-quad notation (digits only – validation done separately)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6: common full and compressed forms
IPV6_REGEX = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"      # full form
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                     # trailing ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"    # ::x
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"   # ::x:y:...
    r"|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}"
    r")\b"
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_ip(ip: str) -> bool:
    """
    Return ``True`` if *ip* is a valid IPv4 or IPv6 address.

    Uses the stdlib ``ipaddress`` module for authoritative validation,
    which also rejects leading-zero ambiguities (e.g. ``192.168.01.1``).
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_ipv4(ip: str) -> bool:
    """Return ``True`` only for valid IPv4 addresses."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_network(cidr: str) -> bool:
    """Return ``True`` if *cidr* is a valid IPv4/IPv6 network prefix."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_ipv4_from_text(text: str) -> Set[str]:
    """
    Extract all valid IPv4 addresses from arbitrary text.

    Returns a deduplicated set of validated IP strings.
    """
    found: Set[str] = set()
    for match in IPV4_REGEX.findall(text):
        if is_valid_ip(match):
            found.add(match)
    return found


def extract_ipv6_from_text(text: str) -> Set[str]:
    """
    Extract all valid IPv6 addresses from arbitrary text.

    Returns a deduplicated set of validated IP strings.
    """
    found: Set[str] = set()
    for match in IPV6_REGEX.findall(text):
        if is_valid_ip(match):
            found.add(match)
    return found


def extract_ips_from_text(text: str) -> Set[str]:
    """
    Extract all valid IPv4 and IPv6 addresses from arbitrary text.

    Convenience wrapper combining both v4 and v6 extraction.
    """
    return extract_ipv4_from_text(text) | extract_ipv6_from_text(text)


# ---------------------------------------------------------------------------
# IP file I/O
# ---------------------------------------------------------------------------

def load_ips_from_file(file_path, *, json_lines: bool = False, json_ip_key: str = "ip") -> Set[str]:
    """
    Load validated IPs from a file.

    Parameters
    ----------
    file_path : Path
        Path to the file.
    json_lines : bool
        If ``True``, treat each line as a JSON object and extract the IP
        from the key specified by *json_ip_key*.
    json_ip_key : str
        JSON key to read when *json_lines* is ``True``.

    Returns
    -------
    set[str]
        Deduplicated set of valid IP address strings.
    """
    import json
    from pathlib import Path

    ips: Set[str] = set()
    file_path = Path(file_path)

    if not file_path.exists():
        return ips

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                if json_lines:
                    try:
                        data = json.loads(line)
                        ip = data.get(json_ip_key, "")
                        if is_valid_ip(ip):
                            ips.add(ip)
                        continue
                    except (json.JSONDecodeError, AttributeError):
                        pass

                # Fallback: regex extraction
                ips |= extract_ips_from_text(line)
    except OSError:
        pass

    return ips


def sorted_ip_list(ips) -> list:
    """
    Return a list of IPs sorted by their packed binary representation.

    Handles mixed IPv4/IPv6 by sorting within each family separately
    then concatenating (v4 first).
    """
    v4 = []
    v6 = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                v4.append(ip)
            else:
                v6.append(ip)
        except (ValueError, TypeError):
            continue

    v4.sort(key=lambda x: ipaddress.ip_address(x).packed)
    v6.sort(key=lambda x: ipaddress.ip_address(x).packed)
    return v4 + v6
