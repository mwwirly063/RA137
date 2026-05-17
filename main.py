from pathlib import Path

from utils.logger import log
from utils.database import init_db
from modules.subdomain_enum import collect_subdomains
from modules.ip_extractor import collect_ips
from utils.paths import create_target_output
from modules.cert_discovery import cert_discovery
from modules.check_cdn import filter_non_cdn_ips
from modules.tech_detect import tech_detection
from modules.realip_discovery import real_ip_discovery

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

        target_output = create_target_output(target)

        collect_subdomains(
            domain=target,
            wordlist_path="wordlists/subdomains.txt",
            output_dir=target_output
        )

        collect_ips(output_dir=target_output)

        filter_non_cdn_ips(output_dir=target_output)

        cert_discovery(
            target=target,
            output_dir=target_output
        )

        tech_detection(
            output_dir=target_output
        )
        
        real_ip_discovery(
            output_dir=target_output
        )

        log(f"Finished target: {target}")

    log("All targets completed")    

if __name__ == "__main__":
    main()