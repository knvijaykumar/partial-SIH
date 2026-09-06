import requests


def geolocate_ip(ip: str) -> dict:

    try:
        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=10
        )

        data = response.json()

        if not data.get("success", False):
            return {
                "ip": ip,
                "success": False,
                "error": data.get(
                    "message",
                    "Geolocation lookup failed"
                )
            }

        return {
            "ip": ip,
            "success": True,
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "isp": data.get("connection", {}).get("isp"),
            "organization": data.get("connection", {}).get("org")
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "success": False,
            "error": str(e)
        }