from pathlib import Path
import ipaddress

from utils.logger import log


PURE_IP_FILE = output_dir / "pure_ip.txt"
FINAL_IP_FILE = output_dir / "ip.txt"

CDN_FILE = Path("wordlists/all_cdn.txt")


def load_cdn_ranges():

    log("Loading CDN ranges")

    cidrs = []

    if not CDN_FILE.exists():
        log("CDN file not found")
        return cidrs

    with open(CDN_FILE, "r") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                cidrs.append(ipaddress.ip_network(line))
            except Exception:
                continue

    log(f"Loaded {len(cidrs)} CDN ranges")

    return cidrs


def is_cdn_ip(ip, cidrs):

    try:

        ip_obj = ipaddress.ip_address(ip)

        for network in cidrs:

            if ip_obj in network:
                return True

        return False

    except Exception:
        return False


def filter_non_cdn_ips():

    log("Filtering CDN IPs")

    if not PURE_IP_FILE.exists():
        log("pure_ip.txt not found")
        return

    cidrs = load_cdn_ranges()

    clean_ips = set()

    with open(PURE_IP_FILE, "r") as f:

        for line in f:

            ip = line.strip()

            if not ip:
                continue

            if not is_cdn_ip(ip, cidrs):
                clean_ips.add(ip)

    with open(FINAL_IP_FILE, "w") as f:

        for ip in sorted(clean_ips):
            f.write(ip + "\n")

    log(f"Saved {len(clean_ips)} non-CDN IPs")