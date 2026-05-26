import ipaddress
import socket
import ssl
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from utils.logger import log


SSL_TIMEOUT = 5

PORTS = [443, 4443, 7443, 8443, 10443]

_write_lock = threading.Lock()


def get_cert_domains(ip, port=443):

    result = {
        "ip": ip,
        "port": port,
        "common_name": None,
        "san": [],
        "error": None
    }

    try:

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=SSL_TIMEOUT) as sock:

            with context.wrap_socket(sock, server_hostname=None) as ssock:

                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            raise Exception("No certificate received")

        cert = x509.load_der_x509_certificate(
            der_cert,
            default_backend()
        )

        try:
            cn = cert.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value

            result["common_name"] = cn

        except IndexError:
            pass

        try:

            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            result["san"] = san_ext.value.get_values_for_type(
                x509.DNSName
            )

        except x509.ExtensionNotFound:
            pass

    except Exception as e:

        result["error"] = str(e)

    return result


def generate_cidr_ips(ip):

    try:

        network = ipaddress.ip_network(f"{ip}/24", strict=False)

        return [str(host) for host in network.hosts()]

    except Exception:

        return []


def is_related(domain, target):

    if not domain:
        return False

    return target.lower() in domain.lower()


def check_ip(ip, target, output_file):

    for port in PORTS:

        result = get_cert_domains(ip, port)

        matched = False

        if is_related(result["common_name"], target):
            matched = True

        for san in result["san"]:
            if is_related(san, target):
                matched = True
                break

        if matched:

            line = (
                f"[MATCH] "
                f"IP={ip} "
                f"PORT={port} "
                f"CN={result['common_name']} "
                f"SAN={','.join(result['san'])}"
            )

            log(line)

            with _write_lock:
                with open(output_file, "a") as f:
                    f.write(line + "\n")


def cert_discovery(target, output_dir):

    log("Starting certificate discovery")

    ip_file = output_dir / "ip.txt"

    output_file = output_dir / "cert_discovery.txt"

    if not ip_file.exists():

        log("ip.txt not found")

        return

    all_ips = set()

    with open(ip_file, "r") as f:

        for line in f:

            ip = line.strip()

            if not ip:
                continue

            all_ips.add(ip)

            cidr_ips = generate_cidr_ips(ip)

            for cidr_ip in cidr_ips:
                all_ips.add(cidr_ip)

    log(f"Checking {len(all_ips)} IPs")

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = [
            executor.submit(
                check_ip,
                ip,
                target,
                output_file
            )
            for ip in all_ips
        ]

        for future in as_completed(futures):
            future.result()

    log("Certificate discovery completed")