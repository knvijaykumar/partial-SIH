import re
import ipaddress


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def extract_ips(forensics: dict) -> list:
    headers = forensics.get("headers", {})
    received_headers = headers.get("received", [])

    ips = []

    for received in received_headers:
        matches = IP_PATTERN.findall(received)

        for ip in matches:
            try:
                ipaddress.ip_address(ip)

                if ip not in ips:
                    ips.append(ip)

            except ValueError:
                pass

    return ips