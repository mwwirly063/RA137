from pathlib import Path

from utils.logger import log
from utils.database import init_db
from modules.subdomain_enum import collect_subdomains
from modules.ip_extractor import collect_ips

TARGETS_FILE = Path("targets.txt")


def load_targets():

    if not TARGETS_FILE.exists():
        log("targets.txt not found")
        return []

    with open(TARGETS_FILE, "r") as f:
        targets = [
            line.strip()
            for line in f
            if line.strip()
        ]

    return targets


def main():

    log("Starting Recon Automation")

    init_db()
    log("Database initialized")

    targets = load_targets()

    if not targets:
        log("No targets found. Exiting.")
        return

    log(f"{len(targets)} targets loaded")

    for target in targets:

        log(f"Processing target: {target}")

        collect_subdomains(
            domain=target,
            wordlist_path="wordlists/subdomains.txt"
        )

        collect_ips()
        
        log(f"Finished target: {target}")

    log("All targets completed")


if __name__ == "__main__":
    main()