from pathlib import Path

from utils.command import run_command
from utils.logger import log
from utils.ai_report import generate_ai_report


def run_subfinder(domain: str, output_dir):

    log(f"Running subfinder on {domain}")

    temp_file = output_dir / "subfinder.txt"

    cmd = f"subfinder -silent -d {domain}"

    run_command(cmd, output_file=temp_file)

    subdomains = set()

    if temp_file.exists():

        with open(temp_file, "r") as f:

            for line in f:

                line = line.strip()

                if line:
                    subdomains.add(line)

    log(f"Subfinder found {len(subdomains)} subdomains")

    return subdomains


def run_gobuster(domain: str, wordlist_path: str, output_dir):

    log(f"Running gobuster on {domain}")

    temp_file = output_dir / "gobuster.txt"

    cmd = (
        f"gobuster dns "
        f"-do {domain} "
        f"-w {wordlist_path} "
        f"--quiet"
    )

    run_command(cmd, output_file=temp_file)

    subdomains = set()

    if temp_file.exists():

        with open(temp_file, "r") as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                sub = line.split()[0]

                if sub:
                    subdomains.add(sub)

    log(f"Gobuster found {len(subdomains)} subdomains")

    return subdomains


def save_subdomains(subdomains: set, output_dir):

    unique_subdomains = sorted(set(subdomains))

    subdomain_file = output_dir / "subdomains.txt"

    with open(subdomain_file, "w") as f:

        for sub in unique_subdomains:
            f.write(sub + "\n")

    log(f"Saved {len(unique_subdomains)} unique subdomains")


def collect_subdomains(domain: str, wordlist_path: str, output_dir):

    log("Starting subdomain collection")

    all_subdomains = set()

    subfinder_results = run_subfinder(domain, output_dir)
    all_subdomains.update(subfinder_results)

    gobuster_results = run_gobuster(
        domain,
        wordlist_path,
        output_dir
    )

    all_subdomains.update(gobuster_results)

    save_subdomains(all_subdomains, output_dir)

    report_data = "\n".join(sorted(all_subdomains))

    generate_ai_report(
        module_name="Subdomain Enumeration",
        data=report_data
    )

    log("Subdomain collection completed")

    return all_subdomains