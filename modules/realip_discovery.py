import base64
import difflib
import ipaddress
import json
import os
import mmh3
import random
import re
import requests
import socket
import ssl
import time
import jarm

from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from urllib.parse import urljoin

try:
    import dns.resolver
except ImportError:
    dns = None

from utils.ai_report import generate_ai_report
from utils.logger import log


requests.packages.urllib3.disable_warnings()


CDN_FILE = "wordlists/all_cdn.txt"

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

REQUEST_DELAY = (1, 3)

SSL_PORTS = [
    443,
    4443,
    7443,
    8443,
    9443,
    10443
]


COMMON_SHARED_CERTS = [
    "cloudflare",
    "akamai",
    "fastly",
    "imperva",
    "amazon",
    "amazonaws",
    "edgekey",
    "cdn"
]


COMMON_SHARED_VHOSTS = [
    "outlook",
    "exchange",
    "owa",
    "autodiscover",
    "cpanel",
    "plesk",
    "webmail"
]


SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
FOFA_EMAIL = os.getenv("FOFA_EMAIL")
FOFA_API_KEY = os.getenv("FOFA_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")

MAX_RESULTS = 500

SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")

session = requests.Session()
session.verify = False
session.headers.update({"User-Agent": "Mozilla/5.0"})

_api_cache = {}


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

                cidrs.append(
                    ipaddress.ip_network(line)
                )

            except Exception as e:
                log(f"CDN range parse error: {e}")
                continue

    return cidrs


def is_cdn_ip(ip, cidrs):

    try:

        ip_obj = ipaddress.ip_address(ip)

        for network in cidrs:

            if ip_obj in network:
                return True

        return False

    except Exception as e:
        log(f"CDN IP check error: {e}")
        return False


def get_favicon_hash(url):

    try:

        rate_limit()

        response = session.get(
            url,
            timeout=10
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

            if (
                link_tag and
                link_tag.get("href")
            ):

                favicon_url = (
                    link_tag.get("href")
                )

                break

        if not favicon_url:

            standard_paths = [
                "/favicon.ico",
                "/favicon.png",
                "/apple-touch-icon.png",
                "/apple-touch-icon-precomposed.png"
            ]

            for path in standard_paths:

                test_url = urljoin(
                    url,
                    path
                )

                try:

                    rate_limit()

                    test_response = session.head(
                        test_url,
                        timeout=5
                    )

                    if (
                        test_response.status_code
                        == 200
                    ):

                        favicon_url = path
                        break

                except Exception as e:
                    log(f"Favicon probe error for {path}: {e}")
                    continue

        if not favicon_url:
            return None

        full_favicon_url = urljoin(
            url,
            favicon_url
        )

        rate_limit()

        favicon_response = session.get(
            full_favicon_url,
            timeout=10
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


def get_ssl_domains(ip,
                    port=443):

    result = set()

    try:

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        context.check_hostname = False

        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (ip, port),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=None
            ) as ssock:

                der_cert = ssock.getpeercert(
                    binary_form=True
                )

        cert = x509.load_der_x509_certificate(
            der_cert,
            default_backend()
        )

        try:

            cn = cert.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value

            result.add(cn.lower())

        except Exception as e:
            log(f"SSL CN extraction error: {e}")

        try:

            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            sans = san_ext.value.get_values_for_type(
                x509.DNSName
            )

            for san in sans:

                result.add(
                    san.lower()
                )

        except Exception as e:
            log(f"SSL SAN extraction error: {e}")

    except Exception as e:
        log(f"SSL connection error for {ip}:{port}: {e}")

    return result


def is_subdomain(sub, parent):

    sub = sub.lower().rstrip(".")
    parent = parent.lower().rstrip(".")

    return (
        sub == parent or
        sub.endswith("." + parent)
    )


def check_certificate_match(
        ip,
        target):

    for port in SSL_PORTS:

        domains = get_ssl_domains(
            ip,
            port
        )

        for domain in domains:

            if is_subdomain(domain, target):

                for item in COMMON_SHARED_CERTS:

                    if item in domain:
                        return False

                return True

    return False


def check_vhost_match(
        ip,
        target):

    try:

        rate_limit()

        response = session.get(
            f"https://{ip}",
            headers={
                "Host": target
            },
            timeout=8
        )

        text = response.text.lower()

        if (
            target.lower()
            in text
        ):

            for item in COMMON_SHARED_VHOSTS:

                if item in text:
                    return False

            return True

    except Exception as e:
        log(f"VHost check error for {ip}: {e}")

    return False


def get_jarm(host):

    hashes = set()

    for port in SSL_PORTS:

        try:

            result = jarm.Scanner.scan(
                host,
                port
            )

            if result and result != "0" * 62:
                hashes.add(result)

        except Exception as e:

            log(f"JARM error on {host}:{port}: {e}")

    return list(hashes)


def shodan_search(query):

    cache_key = f"shodan:{query}"

    if cache_key in _api_cache:
        log(f"Cache hit: {cache_key}")
        return _api_cache[cache_key]

    results = set()

    offset = 0

    try:

        while len(results) < MAX_RESULTS:

            rate_limit()

            url = (
                f"https://api.shodan.io/shodan/host/search"
                f"?key={SHODAN_API_KEY}"
                f"&query={query}"
                f"&offset={offset}"
            )

            response = session.get(
                url,
                timeout=20
            )

            data = response.json()

            matches = data.get("matches", [])

            if not matches:
                break

            for match in matches:

                ip = match.get("ip_str")

                if ip:
                    results.add(ip)

            total = data.get("total", len(matches))

            offset += len(matches)

            if offset >= total:
                break

    except Exception as e:

        log(f"Shodan error: {e}")

    _api_cache[cache_key] = results

    return results


def fofa_search(query):

    cache_key = f"fofa:{query}"

    if cache_key in _api_cache:
        log(f"Cache hit: {cache_key}")
        return _api_cache[cache_key]

    results = set()

    page = 1

    try:

        query_base64 = base64.b64encode(
            query.encode()
        ).decode()

        while len(results) < MAX_RESULTS:

            rate_limit()

            url = (
                f"https://fofa.info/api/v1/search/all"
                f"?email={FOFA_EMAIL}"
                f"&key={FOFA_API_KEY}"
                f"&qbase64={query_base64}"
                f"&page={page}"
            )

            response = session.get(
                url,
                timeout=20
            )

            data = response.json()

            items = data.get("results", [])

            if not items:
                break

            for item in items:

                ip = item[0]

                if re.match(IP_REGEX, ip):
                    results.add(ip)

            total = data.get("size", len(items))

            if page * len(items) >= total:
                break

            page += 1

    except Exception as e:

        log(f"FOFA error: {e}")

    _api_cache[cache_key] = results

    return results


def censys_search(query):

    cache_key = f"censys:{query}"

    if cache_key in _api_cache:
        log(f"Cache hit: {cache_key}")
        return _api_cache[cache_key]

    results = set()

    cursor = None

    try:

        while len(results) < MAX_RESULTS:

            rate_limit()

            url = (
                "https://search.censys.io/api/v2/hosts/search"
            )

            payload = {
                "q": query,
                "per_page": 100
            }

            if cursor:
                payload["cursor"] = cursor

            response = session.post(
                url,
                auth=(
                    CENSYS_API_ID,
                    CENSYS_API_SECRET
                ),
                json=payload,
                timeout=20
            )

            data = response.json()

            result_data = data.get("result", {})

            hits = result_data.get("hits", [])

            if not hits:
                break

            for hit in hits:

                ip = hit.get("ip")

                if ip:
                    results.add(ip)

            cursor = result_data.get("links", {}).get("next")

            if not cursor:
                break

    except Exception as e:

        log(f"Censys error: {e}")

    _api_cache[cache_key] = results

    return results


def build_queries(
        favicon_hash,
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

    jarm_hashes = jarm

    if not isinstance(jarm_hashes, list):
        jarm_hashes = [jarm_hashes] if jarm_hashes else []

    for jarm_hash in jarm_hashes:

        if not jarm_hash:
            continue

        queries.append({
            "type": "jarm",
            "shodan": (
                f"ssl.jarm:{jarm_hash}"
            ),
            "fofa": None,
            "censys": (
                f"services.jarm.fingerprint:{jarm_hash}"
            )
        })

    return queries


def check_body_similarity(ip, target):

    try:

        rate_limit()

        cdn_response = session.get(
            f"https://{target}",
            timeout=10,
            allow_redirects=True
        )

        rate_limit()

        ip_response = session.get(
            f"https://{ip}",
            headers={"Host": target},
            timeout=10,
            allow_redirects=True
        )

        if (
            cdn_response.status_code != 200 or
            ip_response.status_code != 200
        ):
            return False

        cdn_text = cdn_response.text[:5000]
        ip_text = ip_response.text[:5000]

        ratio = difflib.SequenceMatcher(
            None,
            cdn_text,
            ip_text
        ).ratio()

        log(f"Body similarity {ip} vs {target}: {ratio:.2f}")

        return ratio >= 0.6

    except Exception as e:

        log(f"Body similarity error for {ip}: {e}")

        return False


def get_cname_ips(domain):

    results = set()

    if dns is None:
        log("dnspython not installed, skipping CNAME analysis")
        return results

    try:

        try:
            answers = dns.resolver.resolve(domain, "CNAME")
        except Exception as e:
            log(f"CNAME resolve error for {domain}: {e}")
            return results

        for rdata in answers:

            cname = str(rdata.target).rstrip(".")

            log(f"CNAME chain: {domain} -> {cname}")

            try:
                a_answers = dns.resolver.resolve(cname, "A")

                for a_record in a_answers:
                    ip = str(a_record)
                    results.add(ip)

            except Exception as e:
                log(f"CNAME A-record error for {cname}: {e}")

    except Exception as e:
        log(f"CNAME analysis error for {domain}: {e}")

    return results


def securitytrails_history(domain):

    results = set()

    if not SECURITYTRAILS_API_KEY:
        return results

    cache_key = f"securitytrails:{domain}"

    if cache_key in _api_cache:
        log(f"Cache hit: {cache_key}")
        return _api_cache[cache_key]

    try:

        rate_limit()

        url = (
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        )

        response = session.get(
            url,
            headers={
                "APIKEY": SECURITYTRAILS_API_KEY,
                "Accept": "application/json"
            },
            timeout=20
        )

        if response.status_code != 200:
            log(f"SecurityTrails returned {response.status_code}")
            return results

        data = response.json()

        for record in data.get("records", []):

            for value in record.get("values", []):

                ip = value.get("ip")

                if ip:
                    results.add(ip)

    except Exception as e:
        log(f"SecurityTrails error for {domain}: {e}")

    _api_cache[cache_key] = results

    return results


def validate_real_ip(
        ip,
        target,
        favicon_match=False,
        cert_match=False,
        vhost_match=False,
        jarm_match=False,
        body_match=False):

    score = 0

    if favicon_match:
        score += 1

    if jarm_match:
        score += 2

    if body_match:
        score += 3

    if vhost_match:
        score += 4

    if cert_match:
        score += 5

    return score >= 7, score


def save_results(results,
                 output_file):

    with open(output_file, "w") as f:

        for item in results:

            f.write(
                json.dumps(item) + "\n"
            )

    log(
        f"Saved {len(results)} results"
    )


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

    def process_subdomain(target):

        log(
            f"Fingerprinting {target}"
        )

        url = f"https://{target}"

        favicon_hash = get_favicon_hash(
            url
        )

        jarm_hashes = get_jarm(
            target
        )

        queries = build_queries(
            favicon_hash,
            jarm_hashes
        )

        favicon_ips = set()

        jarm_ips = set()

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

                    if query_type == "favicon":
                        favicon_ips.update(results)
                    elif query_type == "jarm":
                        jarm_ips.update(results)

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

                    if query_type == "favicon":
                        favicon_ips.update(results)
                    elif query_type == "jarm":
                        jarm_ips.update(results)

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

                    if query_type == "favicon":
                        favicon_ips.update(results)
                    elif query_type == "jarm":
                        jarm_ips.update(results)

        # CNAME chain analysis
        cname_ips = get_cname_ips(target)

        # SecurityTrails DNS history
        history_ips = securitytrails_history(target)

        target_results = favicon_ips | jarm_ips | cname_ips | history_ips

        target_results_list = []

        for ip in target_results:

            cert_match = check_certificate_match(
                ip,
                target
            )

            vhost_match = check_vhost_match(
                ip,
                target
            )

            body_match = check_body_similarity(
                ip,
                target
            )

            valid, score = validate_real_ip(
                ip=ip,
                target=target,
                favicon_match=(ip in favicon_ips),
                cert_match=cert_match,
                vhost_match=vhost_match,
                jarm_match=(ip in jarm_ips),
                body_match=body_match
            )

            if not valid:
                continue

            result = {
                "target": target,
                "ip": ip,
                "score": score,
                "cert_match": cert_match,
                "vhost_match": vhost_match,
                "body_match": body_match,
                "matched_by": matched_by
            }

            target_results_list.append(result)

        return target_results_list

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = {
            executor.submit(process_subdomain, sub): sub
            for sub in subdomains
        }

        for future in as_completed(futures):

            try:

                results = future.result()
                all_results.extend(results)

            except Exception as e:

                sub = futures[future]
                log(f"Error processing {sub}: {e}")

    save_results(
        all_results,
        output_file
    )

    report_data = "\n".join([
        json.dumps(x)
        for x in all_results
    ])

    generate_ai_report(
        module_name="Real IP Discovery",
        data=report_data
    )

    log("Real IP discovery completed")
