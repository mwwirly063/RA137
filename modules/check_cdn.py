from pathlib import Path
import ipaddress

from utils.logger import log


CDN_FILE = Path("wordlists/all_cdn.txt")


def load_cdn_ranges():

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

    return cidrs


def is_cdn_ip(ip, cidrs):

    try:

        ip_obj = ipaddress.ip_address(ip)

        for net in cidrs:
            if ip_obj in net:
                return True

        return False

    except Exception:
        return False


def filter_non_cdn_ips(output_dir):

    log("Filtering CDN IPs")

    pure_ip_file = output_dir / "pure_ip.txt"
    final_ip_file = output_dir / "ip.txt"

    if not pure_ip_file.exists():
        log("pure_ip.txt not found")
        return

    cidrs = load_cdn_ranges()

    clean_ips = set()

    with open(pure_ip_file, "r") as f:

        for line in f:

            ip = line.strip()

            if not ip:
                continue

            if not is_cdn_ip(ip, cidrs):
                clean_ips.add(ip)

    with open(final_ip_file, "w") as f:

        for ip in sorted(clean_ips):
            f.write(ip + "\n")

    log(f"Saved {len(clean_ips)} non-CDN IPs")