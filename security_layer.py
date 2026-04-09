import dns.resolver
import ssl
import socket
import requests
from datetime import datetime

# 🔥 LOAD TRUSTED DOMAINS FROM FILE
def load_trusted_domains():
    try:
        with open("trusted_domains.txt", "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except:
        return []

TRUSTED_DOMAINS = load_trusted_domains()


# ✅ SAFE TRUST CHECK
def is_trusted_domain(domain):
    domain = domain.replace("www.", "").lower()

    for trusted in TRUSTED_DOMAINS:

        # Exact match
        if domain == trusted:
            return True

        # Subdomain support
        if domain.endswith("." + trusted):
            return True

    return False


# Extract domain
def extract_domain(url):
    domain = url.replace("https://", "").replace("http://", "")
    return domain.split("/")[0].lower()


# DNS check
def has_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False


# SSL check
def has_ssl(domain):
    try:
        ctx = ssl.create_default_context()

        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    return True
        except:
            pass

        try:
            with socket.create_connection(("www." + domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="www." + domain):
                    return True
        except:
            pass

        return False

    except:
        return False


# Domain age (RDAP)
def get_domain_age(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return 0

        data = response.json()

        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate")
                creation_date = datetime.fromisoformat(date_str.replace("Z", ""))
                return (datetime.now() - creation_date).days

        return 0

    except:
        return 0
