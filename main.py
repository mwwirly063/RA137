from pathlib import Path

from utils.logger import log
from utils.database import init_db
from utils.paths import create_target_output

from modules.subdomain_enum import collect_subdomains
from modules.ip_extractor import collect_ips
from modules.cert_discovery import cert_discovery
from modules.check_cdn import filter_non_cdn_ips
from modules.tech_detect import tech_detection
from modules.realip_discovery import real_ip_discovery
from modules.vuln_check import nuclei_scan


TARGETS_FILE = Path("targets.txt")

LOG_FILE = Path("recon.log")


STEPS = [
    "subdomain_enum",
    "ip_extractor",
    "check_cdn",
    "cert_discovery",
    "tech_detection",
    "realip_discovery",
    "vuln_check"
]


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


def load_log():

    if not LOG_FILE.exists():
        return ""

    with open(LOG_FILE, "r") as f:
        return f.read()


def step_completed(log_data,
                   target,
                   step):

    check = (
        f"[DONE] "
        f"{target} "
        f"{step}"
    )

    return check in log_data


def mark_step_done(target,
                   step):

    log(
        f"[DONE] "
        f"{target} "
        f"{step}"
    )


def main():

    log("Starting Recon Automation")

    init_db()

    log("Database initialized")

    targets = load_targets()

    if not targets:

        log("No targets found")

        return

    log(
        f"{len(targets)} targets loaded"
    )

    log_data = load_log()

    for target in targets:

        log(
            f"Processing target: {target}"
        )

        target_output = create_target_output(
            target
        )

        if not step_completed(
            log_data,
            target,
            "subdomain_enum"
        ):

            collect_subdomains(
                domain=target,
                wordlist_path=(
                    "wordlists/subdomains.txt"
                ),
                output_dir=target_output
            )

            mark_step_done(
                target,
                "subdomain_enum"
            )

        if not step_completed(
            log_data,
            target,
            "ip_extractor"
        ):

            collect_ips(
                output_dir=target_output
            )

            mark_step_done(
                target,
                "ip_extractor"
            )

        if not step_completed(
            log_data,
            target,
            "check_cdn"
        ):

            filter_non_cdn_ips(
                output_dir=target_output
            )

            mark_step_done(
                target,
                "check_cdn"
            )

        if not step_completed(
            log_data,
            target,
            "cert_discovery"
        ):

            cert_discovery(
                target=target,
                output_dir=target_output
            )

            mark_step_done(
                target,
                "cert_discovery"
            )

        if not step_completed(
            log_data,
            target,
            "tech_detection"
        ):

            tech_detection(
                output_dir=target_output
            )

            mark_step_done(
                target,
                "tech_detection"
            )

        if not step_completed(
            log_data,
            target,
            "realip_discovery"
        ):

            real_ip_discovery(
                output_dir=target_output
            )

            mark_step_done(
                target,
                "realip_discovery"
            )

        if not step_completed(
            log_data,
            target,
            "vuln_check"
        ):

            nuclei_scan(
                output_dir=target_output
            )

            mark_step_done(
                target,
                "vuln_check"
            )

        log(
            f"Finished target: {target}"
        )

    log("All targets completed")


if __name__ == "__main__":

    main()