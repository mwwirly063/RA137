import json
import re

from utils.command import run_command
from utils.logger import log
from utils.ai_report import generate_ai_report
from utils.telegram_alert import (
    send_nuclei_results_to_telegram
)


IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"


PORTS = [
    80,
    443,
    4443,
    7443,
    8443,
    9443,
    10443
]


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

    files = [
        output_dir / "ip.txt",
        output_dir / "realip.txt",
        output_dir / "cert_discovery.txt"
    ]

    all_ips = set()

    for file_path in files:

        ips = extract_ips_from_file(
            file_path
        )

        all_ips.update(ips)

    return sorted(all_ips)


def build_targets(ips):

    targets = set()

    for ip in ips:

        for port in PORTS:

            if port == 80:

                targets.add(
                    f"http://{ip}"
                )

            elif port == 443:

                targets.add(
                    f"https://{ip}"
                )

            else:

                targets.add(
                    f"https://{ip}:{port}"
                )

    return sorted(targets)


def save_targets(targets, output_dir):

    input_file = (
        output_dir / "nuclei_targets.txt"
    )

    with open(input_file, "w") as f:

        for target in targets:
            f.write(target + "\n")

    return input_file


def run_nuclei(input_file, output_dir):

    output_file = (
        output_dir / "nuclei_results.txt"
    )

    json_file = (
        output_dir / "nuclei_results.json"
    )

    cmd = (
        f"nuclei "
        f"-l {input_file} "
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

    log(
        f"Collected {len(ips)} IPs"
    )

    targets = build_targets(
        ips
    )

    log(
        f"Built {len(targets)} targets"
    )

    input_file = save_targets(
        targets,
        output_dir
    )

    output_file = run_nuclei(
        input_file,
        output_dir
    )

    findings = parse_nuclei_results(
        output_file
    )

    report_data = "\n".join(
        findings
    )

    generate_ai_report(
        module_name="Nuclei Scan",
        data=report_data
    )

    send_nuclei_results_to_telegram(
        output_dir
    )

    log(
        f"Nuclei found "
        f"{len(findings)} results"
    )

    log("Nuclei scan completed")