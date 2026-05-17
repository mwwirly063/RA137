from pathlib import Path

from utils.command import run_command
from utils.logger import log
from utils.ai_report import generate_ai_report

WAF_KEYWORDS = [
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "f5",
    "fastly",
    "aws",
    "edge"
]


IIS_DEFAULT_KEYWORDS = [
    "iis windows server",
    "welcome to iis",
    "internet information services"
]


OTHER_DEFAULT_KEYWORDS = [
    "apache2 ubuntu default page",
    "nginx welcome",
    "test page",
    "default page",
    "placeholder page",
    "it works",
    "welcome page"
]


PORTS = "80,443,4443,7443,8443,9443,10443"


def run_httpx(subdomain_file, output_file):

    log("Running tech detection with httpx")

    cmd = (
        f"httpxx "
        f"-l {subdomain_file} "
        f"-ports {PORTS} "
        f"-title "
        f"-server "
        f"-tech-detect "
        f"-silent "
        f"-o {output_file}"
    )

    run_command(cmd)

    log("httpx tech detection completed")


def parse_httpx_results(httpx_file,
                        waf_file,
                        iis_file,
                        other_default_file):

    log("Parsing tech detection results")

    waf_results = set()

    iis_results = set()

    other_default_results = set()

    if not httpx_file.exists():
        return

    with open(httpx_file, "r", encoding="utf-8") as f:

        for line in f:

            lower_line = line.lower()

            for waf in WAF_KEYWORDS:

                if waf in lower_line:
                    waf_results.add(line.strip())

            for keyword in IIS_DEFAULT_KEYWORDS:

                if keyword in lower_line:
                    iis_results.add(line.strip())

            for keyword in OTHER_DEFAULT_KEYWORDS:

                if keyword in lower_line:
                    other_default_results.add(line.strip())

    with open(waf_file, "w") as f:

        for item in sorted(waf_results):
            f.write(item + "\n")

    with open(iis_file, "w") as f:

        for item in sorted(iis_results):
            f.write(item + "\n")

    with open(other_default_file, "w") as f:

        for item in sorted(other_default_results):
            f.write(item + "\n")

    log(f"WAF results: {len(waf_results)}")
    log(f"IIS default pages: {len(iis_results)}")
    log(f"Other default pages: {len(other_default_results)}")


def run_gow(ip_file):

    log("Running gow screenshot scan")


     cmd = (
        f"cd {output_dir} && "
        f"gow scan file "
        f"-f ip.txt "
        f"--screenshot-fullpage"
    )

    run_command(cmd)

    log("gow screenshot scan completed")


def tech_detection(output_dir):

    log("Starting tech detection")

    subdomain_file = output_dir / "subdomains.txt"

    ip_file = output_dir / "ip.txt"

    pure_httpx_file = output_dir / "pure_httpx.txt"

    waf_file = output_dir / "waf.txt"

    iis_file = output_dir / "iis_defaultpage.txt"

    other_default_file = output_dir / "other_defaultpage.txt"

    run_httpx(
        subdomain_file,
        pure_httpx_file
    )

    parse_httpx_results(
        pure_httpx_file,
        waf_file,
        iis_file,
        other_default_file
    )

    run_gow(
        ip_file,
        output_dir
    )

    log("Tech detection completed")