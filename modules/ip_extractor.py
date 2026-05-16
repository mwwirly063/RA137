import re

from utils.command import run_command
from utils.logger import log


IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"


def run_dnsx(subdomain_file, dnsx_file):

    log("Running dnsx")

    cmd = (
        f"dnsx "
        f"-l {subdomain_file} "
        f"-resp "
        f"-silent "
        f"-o {dnsx_file}"
    )

    run_command(cmd)

    log("dnsx completed")


def run_httpx(subdomain_file, httpx_file):

    log("Running httpx")

    cmd = (
        f"httpxx "
        f"-l {subdomain_file} "
        f"-ip "
        f"-silent "
        f"-o {httpx_file}"
    )

    run_command(cmd)

    log("httpx completed")


def extract_ips(dnsx_file, httpx_file, pure_ip_file):

    log("Extracting IP addresses")

    all_ips = set()

    files = [dnsx_file, httpx_file]

    for file_path in files:

        if not file_path.exists():
            continue

        with open(file_path, "r") as f:

            content = f.read()

            matches = re.findall(IP_REGEX, content)

            for ip in matches:
                all_ips.add(ip)

    with open(pure_ip_file, "w") as f:

        for ip in sorted(all_ips):
            f.write(ip + "\n")

    log(f"Saved {len(all_ips)} unique IPs")


def collect_ips(output_dir):

    subdomain_file = output_dir / "subdomains.txt"

    dnsx_file = output_dir / "dns1.txt"

    httpx_file = output_dir / "dns2.txt"

    pure_ip_file = output_dir / "pure_ip.txt"

    log("Starting IP collection")

    run_dnsx(subdomain_file, dnsx_file)

    run_httpx(subdomain_file, httpx_file)

    extract_ips(
        dnsx_file,
        httpx_file,
        pure_ip_file
    )

    log("IP collection completed")