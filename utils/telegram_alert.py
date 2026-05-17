import json
import requests

from utils.logger import log


TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""


def send_telegram_alert(target, ip, vuln_info):

    try:

        severity = vuln_info.get(
            "info",
            {}
        ).get(
            "severity",
            "unknown"
        )

        name = vuln_info.get(
            "info",
            {}
        ).get(
            "name",
            "unknown"
        )

        template_id = vuln_info.get(
            "template-id",
            "unknown"
        )

        matched_at = vuln_info.get(
            "matched-at",
            "N/A"
        )

        curl_command = vuln_info.get(
            "curl-command",
            "N/A"
        )

        message = f"""
🚨 VULNERABILITY ALERT 🚨

Target: {target}
IP: {ip}

Severity: {severity}
Name: {name}
Template: {template_id}

URL: {matched_at}

Curl:
{curl_command}
"""

        url = (
            f"https://api.telegram.org/bot"
            f"{TELEGRAM_BOT_TOKEN}"
            f"/sendMessage"
        )

        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message
        }

        requests.post(
            url,
            json=payload,
            timeout=10
        )

        log(
            f"Telegram alert sent for {ip}"
        )

    except Exception as e:

        log(
            f"Telegram alert failed: {e}"
        )


def send_nuclei_results_to_telegram(
        output_dir):

    json_file = (
        output_dir /
        "nuclei_results.json"
    )

    if not json_file.exists():

        log(
            "nuclei_results.json not found"
        )

        return

    with open(json_file, "r") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:

                vuln_info = json.loads(line)

                ip = vuln_info.get(
                    "ip",
                    "unknown"
                )

                target = vuln_info.get(
                    "host",
                    ip
                )

                send_telegram_alert(
                    target,
                    ip,
                    vuln_info
                )

            except Exception as e:

                log(
                    f"Telegram parse error: {e}"
                )
