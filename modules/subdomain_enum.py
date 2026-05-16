from pathlib import Path

from utils.command import run_command
from utils.logger import log
from utils.ai_report import generate_ai_report


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

SUBDOMAIN_FILE = output_dir / "subdomains.txt"


def run_subfinder(domain: str):

    log(f"Running subfinder on {domain}")

    cmd = f"subfinder -silent -d {domain}"

    temp_file = OUTPUT_DIR / "subfinder.txt"

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


def run_gobuster(domain: str, wordlist_path: str):

    log(f"Running gobuster on {domain}")

    cmd = (
        f"gobuster dns "
        f"-d {domain} "
        f"-w {wordlist_path} "
        f"--quiet"
    )

    temp_file = OUTPUT_DIR / "gobuster.txt"

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


def save_subdomains(subdomains: set):

    unique_subdomains = sorted(set(subdomains))

    with open(SUBDOMAIN_FILE, "w") as f:
        for sub in unique_subdomains:
            f.write(sub + "\n")

    log(f"Saved {len(unique_subdomains)} unique subdomains")


def collect_subdomains(domain: str, wordlist_path: str, output_dir):

    log("Starting subdomain collection")

    all_subdomains = set()

    subfinder_results = run_subfinder(domain)
    all_subdomains.update(subfinder_results)

    gobuster_results = run_gobuster(domain, wordlist_path)
    all_subdomains.update(gobuster_results)

    save_subdomains(all_subdomains)

    report_data = "\n".join(sorted(all_subdomains))

    generate_ai_report(
        module_name="Subdomain Enumeration",
        data=report_data
    )

    log("Subdomain collection completed")

    return all_subdomains