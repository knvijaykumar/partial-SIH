import requests


def analyze_domain(domain: str) -> dict:

    domain = domain.lower().strip()

    url = f"https://rdap.org/domain/{domain}"

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={
                "Accept": "application/rdap+json"
            }
        )

        if response.status_code != 200:
            return {
                "domain": domain,
                "available": False,
                "error": f"RDAP lookup failed: {response.status_code}"
            }

        data = response.json()

        events = {}

        for event in data.get("events", []):
            event_action = event.get("eventAction")
            event_date = event.get("eventDate")

            if event_action and event_date:
                events[event_action] = event_date

        nameservers = []

        for nameserver in data.get("nameservers", []):
            hostname = nameserver.get("ldhName")

            if hostname:
                nameservers.append(hostname)

        return {
            "domain": domain,
            "available": True,
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "events": events,
            "nameservers": nameservers
        }

    except requests.RequestException as e:
        return {
            "domain": domain,
            "available": False,
            "error": str(e)
        }