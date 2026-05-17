import json
import re

from pathlib import Path

from utils.command import run_command
from utils.logger import log
from utils.ai_report import generate_ai_report


IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"


def extract_ips_from_file(file_path):

    ips = set()

    if not file_path.exists():
        return ips

    with open(file_path, "r") as f:

        for line in f:

            found = re.findall(
                IP_REGEX,
                line
            )

            for ip in found:
                ips.add(ip)

    return ips


def collect_all_ips(output_dir):

    ip_files = [
        output_dir / "ip.txt",
        output_dir / "realip.txt",
        output_dir / "cert_discovery.txt"
    ]

    all_ips = set()

    for file_path in ip_files:

        ips = extract_ips_from_file(
            file_path
        )

        all_ips.update(ips)

    return sorted(all_ips)


def save_ips(ips, output_dir):

    nuclei_input = (
        output_dir / "nuclei_ips.txt"
    )

    with open(nuclei_input, "w") as f:

        for ip in ips:
            f.write(ip + "\n")

    return nuclei_input


def run_nuclei(nuclei_input, output_dir):

    output_file = (
        output_dir / "nuclei_results.txt"
    )

    json_file = (
        output_dir / "nuclei_results.json"
    )

    cmd = (
        f"nuclei "
        f"-l {nuclei_input} "
        f"-silent "
        f"-o {output_file} "
        f"-json-export {json_file}"
    )

    log("Running nuclei")

    run_command(cmd)

    log("Nuclei scan completed")

    return output_file


def parse_nuclei_results(output_file):

    findings = []

    if not output_file.exists():
        return findings

    with open(output_file, "r") as f:

        for line in f:

            line = line.strip()

            if line:
                findings.append(line)

    return findings


def nuclei_scan(output_dir):

    log("Starting nuclei scan")

    ips = collect_all_ips(
        output_dir
    )

    if not ips:

        log("No IPs found")
        return

    log(f"Collected {len(ips)} IPs")

    nuclei_input = save_ips(
        ips,
        output_dir
    )

    output_file = run_nuclei(
        nuclei_input,
        output_dir
    )

    findings = parse_nuclei_results(
        output_file
    )

    report_data = "\n".join(findings)

    generate_ai_report(
        module_name="Nuclei Scan",
        data=report_data
    )

    log(
        f"Nuclei found "
        f"{len(findings)} results"
    )

    log("Nuclei scan completed")