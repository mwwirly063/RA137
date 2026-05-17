import base64
import ipaddress
import json
import mmh3
import random
import re
import requests
import socket
import ssl
import time
import jarm

from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urljoin
from utils.ai_report import generate_ai_report

from utils.logger import log


requests.packages.urllib3.disable_warnings()


CDN_FILE = "wordlists/all_cdn.txt"

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

REQUEST_DELAY = (1, 3)

SHODAN_API_KEY = ""
FOFA_EMAIL = ""
FOFA_API_KEY = ""
CENSYS_API_ID = ""
CENSYS_API_SECRET = ""


def rate_limit():

    delay = random.uniform(
        REQUEST_DELAY[0],
        REQUEST_DELAY[1]
    )

    time.sleep(delay)


def load_cdn_ranges():

    cidrs = []

    with open(CDN_FILE, "r") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                cidrs.append(ipaddress.ip_network(line))
            except Exception:
                continue

    return cidrs


def is_cdn_ip(ip, cidrs):

    try:

        ip_obj = ipaddress.ip_address(ip)

        for network in cidrs:

            if ip_obj in network:
                return True

        return False

    except Exception:
        return False


def get_favicon_hash(url):

    try:

        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        rate_limit()

        response = requests.get(
            url,
            timeout=10,
            headers=headers,
            verify=False
        )

        if response.status_code != 200:
            return None

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        favicon_url = None

        favicon_tags = [
            {"rel": "icon"},
            {"rel": "shortcut icon"},
            {"rel": "apple-touch-icon"},
            {"rel": "apple-touch-icon-precomposed"},
        ]

        for tag_attrs in favicon_tags:

            link_tag = soup.find(
                "link",
                rel=lambda x:
                x and tag_attrs["rel"] in x.lower()
                if x else False
            )

            if link_tag and link_tag.get("href"):

                favicon_url = link_tag.get("href")
                break

        if not favicon_url:

            standard_paths = [
                "/favicon.ico",
                "/favicon.png",
                "/apple-touch-icon.png",
                "/apple-touch-icon-precomposed.png"
            ]

            for path in standard_paths:

                test_url = urljoin(url, path)

                try:

                    rate_limit()

                    test_response = requests.head(
                        test_url,
                        timeout=5,
                        headers=headers,
                        verify=False
                    )

                    if test_response.status_code == 200:

                        favicon_url = path
                        break

                except Exception:
                    continue

        if not favicon_url:
            return None

        full_favicon_url = urljoin(
            url,
            favicon_url
        )

        rate_limit()

        favicon_response = requests.get(
            full_favicon_url,
            timeout=10,
            headers=headers,
            verify=False
        )

        if favicon_response.status_code != 200:
            return None

        favicon_base64 = base64.encodebytes(
            favicon_response.content
        )

        favicon_hash = mmh3.hash(
            favicon_base64
        )

        return favicon_hash

    except Exception as e:

        log(f"Favicon error: {e}")

        return None



def get_cert_fingerprint(host, port=443):

    try:

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        context.check_hostname = False

        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (host, port),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as ssock:

                der_cert = ssock.getpeercert(
                    binary_form=True
                )

        cert = x509.load_der_x509_certificate(
            der_cert,
            default_backend()
        )

        sha256 = cert.fingerprint(
            cert.signature_hash_algorithm
        ).hex()

        return sha256

    except Exception:
        return None


def get_jarm(host, port=443):

    try:

        result = jarm.Scanner.scan(
            host,
            port
        )

        return result

    except Exception:
        return None


def shodan_search(query):

    results = set()

    try:

        rate_limit()

        url = (
            f"https://api.shodan.io/shodan/host/search"
            f"?key={SHODAN_API_KEY}"
            f"&query={query}"
        )

        response = requests.get(
            url,
            timeout=20
        )

        data = response.json()

        for match in data.get("matches", []):

            ip = match.get("ip_str")

            if ip:
                results.add(ip)

    except Exception as e:

        log(f"Shodan error: {e}")

    return results


def fofa_search(query):

    results = set()

    try:

        query_base64 = base64.b64encode(
            query.encode()
        ).decode()

        rate_limit()

        url = (
            f"https://fofa.info/api/v1/search/all"
            f"?email={FOFA_EMAIL}"
            f"&key={FOFA_API_KEY}"
            f"&qbase64={query_base64}"
        )

        response = requests.get(
            url,
            timeout=20
        )

        data = response.json()

        for item in data.get("results", []):

            ip = item[0]

            if re.match(IP_REGEX, ip):
                results.add(ip)

    except Exception as e:

        log(f"FOFA error: {e}")

    return results


def censys_search(query):

    results = set()

    try:

        rate_limit()

        url = (
            "https://search.censys.io/api/v2/hosts/search"
        )

        payload = {
            "q": query,
            "per_page": 100
        }

        response = requests.post(
            url,
            auth=(
                CENSYS_API_ID,
                CENSYS_API_SECRET
            ),
            json=payload,
            timeout=20
        )

        data = response.json()

        hits = data.get(
            "result",
            {}
        ).get(
            "hits",
            []
        )

        for hit in hits:

            ip = hit.get("ip")

            if ip:
                results.add(ip)

    except Exception as e:

        log(f"Censys error: {e}")

    return results


def build_queries(favicon_hash,
                  title,
                  cert_hash,
                  jarm):

    queries = []

    if favicon_hash:

        queries.append({
            "type": "favicon",
            "shodan": (
                f"http.favicon.hash:{favicon_hash}"
            ),
            "fofa": (
                f'icon_hash="{favicon_hash}"'
            ),
            "censys": (
                "services.http.response."
                f"favicons.mmh3_hash:{favicon_hash}"
            )
        })

    if title:

        queries.append({
            "type": "title",
            "shodan": (
                f'http.title:"{title}"'
            ),
            "fofa": (
                f'title="{title}"'
            ),
            "censys": (
                "services.http.response."
                f"html_title:{title}"
            )
        })

    if cert_hash:

        queries.append({
            "type": "cert",
            "shodan": (
                f"ssl.cert.fingerprint:{cert_hash}"
            ),
            "fofa": None,
            "censys": (
                "services.tls.certificates."
                f"leaf_data.fingerprint:{cert_hash}"
            )
        })

    if jarm:

        queries.append({
            "type": "jarm",
            "shodan": (
                f"ssl.jarm:{jarm}"
            ),
            "fofa": None,
            "censys": (
                f"services.jarm.fingerprint:{jarm}"
            )
        })

    return queries


def save_results(results, output_file):

    with open(output_file, "w") as f:

        for item in results:

            f.write(
                json.dumps(item) + "\n"
            )

    log(f"Saved {len(results)} results")


def real_ip_discovery(output_dir):

    log("Starting real IP discovery")

    subdomain_file = (
        output_dir / "subdomains.txt"
    )

    pure_ip_file = (
        output_dir / "pure_ip.txt"
    )

    output_file = (
        output_dir / "realip.txt"
    )

    cidrs = load_cdn_ranges()

    if not pure_ip_file.exists():
        return

    cdn_ips = []

    with open(pure_ip_file, "r") as f:

        for line in f:

            ip = line.strip()

            if (
                ip and
                is_cdn_ip(ip, cidrs)
            ):
                cdn_ips.append(ip)

    if not cdn_ips:
        return

    if not subdomain_file.exists():
        return

    subdomains = []

    with open(subdomain_file, "r") as f:

        for line in f:

            sub = line.strip()

            if sub:
                subdomains.append(sub)

    all_results = []

    for target in subdomains:

        url = f"https://{target}"

        log(f"Fingerprinting {target}")

        favicon_hash = get_favicon_hash(url)

        cert_hash = get_cert_fingerprint(
            target
        )

        jarm = get_jarm(target)

        queries = build_queries(
            favicon_hash,
            title,
            cert_hash,
            jarm
        )

        target_results = set()

        matched_by = []

        for query in queries:

            query_type = query["type"]

            if (
                SHODAN_API_KEY and
                query["shodan"]
            ):

                results = shodan_search(
                    query["shodan"]
                )

                if results:

                    matched_by.append(
                        f"shodan-{query_type}"
                    )

                    target_results.update(
                        results
                    )

            if (
                FOFA_EMAIL and
                FOFA_API_KEY and
                query["fofa"]
            ):

                results = fofa_search(
                    query["fofa"]
                )

                if results:

                    matched_by.append(
                        f"fofa-{query_type}"
                    )

                    target_results.update(
                        results
                    )

            if (
                CENSYS_API_ID and
                CENSYS_API_SECRET and
                query["censys"]
            ):

                results = censys_search(
                    query["censys"]
                )

                if results:

                    matched_by.append(
                        f"censys-{query_type}"
                    )

                    target_results.update(
                        results
                    )

        for ip in target_results:

            result = {
                "target": target,
                "ip": ip,
                "score": len(matched_by) * 10,
                "matched_by": matched_by
            }

            all_results.append(result)

    save_results(
        all_results,
        output_file
    )

    log("Real IP discovery completed")