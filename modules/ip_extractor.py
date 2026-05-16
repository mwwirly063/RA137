import re
from pathlib import Path

from utils.command import run_command
from utils.logger import log

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"


def run_dnsx():

    log("Running dnsx")

    cmd = (
        f"dnsx "
        f"-l {SUBDOMAIN_FILE} "
        f"-resp "
        f"-silent "
        f"-o {DNSX_FILE}"
    )

    run_command(cmd)

    log("dnsx completed")


def run_httpx():

    log("Running httpx")

    cmd = (
        f"httpx "
        f"-l {SUBDOMAIN_FILE} "
        f"-ip "
        f"-silent "
        f"-o {HTTPX_FILE}"
    )

    run_command(cmd)

    log("httpx completed")


def extract_ips():

    log("Extracting IP addresses")

    all_ips = set()

    files = [DNSX_FILE, HTTPX_FILE]

    for file_path in files:

        if not file_path.exists():
            continue

        with open(file_path, "r") as f:

            content = f.read()

            matches = re.findall(IP_REGEX, content)

            for ip in matches:
                all_ips.add(ip)

    with open(PURE_IP_FILE, "w") as f:
        for ip in sorted(all_ips):
            f.write(ip + "\n")

    log(f"Saved {len(all_ips)} unique IPs")


def collect_ips(output_dir):

    SUBDOMAIN_FILE = output_dir / "subdomains.txt"

    DNSX_FILE = output_dir / "dns1.txt"
    HTTPX_FILE = output_dir / "dns2.txt"

    PURE_IP_FILE = output_dir / "pure_ip.txt"

    log("Starting IP collection")

    run_dnsx()

    run_httpx()

    extract_ips()

    log("IP collection completed")