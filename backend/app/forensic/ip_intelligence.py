import ipaddress


def analyze_ip(ip: str) -> dict:

    try:
        address = ipaddress.ip_address(ip)

        return {
            "ip": ip,
            "version": address.version,
            "public": address.is_global,
            "private": address.is_private,
            "loopback": address.is_loopback,
            "reserved": address.is_reserved
        }

    except ValueError:
        return {
            "ip": ip,
            "error": "Invalid IP address"
        }