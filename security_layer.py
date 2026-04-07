import dns.resolver
import ssl
import socket
import requests
from datetime import datetime

# 🔥 TRUSTED DOMAINS (EXACT MATCH ONLY)
TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "instagram.com",
    "yahoo.com", "amazon.com", "twitter.com",
    "linkedin.com", "netflix.com",
    "dituniversity.edu.in", "diterp.dituniversity.edu.in"
]

# ✅ FIXED TRUSTED DOMAIN CHECK
def is_trusted_domain(domain):
    domain = domain.replace("www.", "").lower()
    return domain in TRUSTED_DOMAINS


# Extract domain
def extract_domain(url):
    domain = url.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    return domain.lower()


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


# RDAP domain age
def get_domain_age(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return 0

        data = response.json()
        events = data.get("events", [])

        for event in events:
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate")
                creation_date = datetime.fromisoformat(date_str.replace("Z", ""))
                age = (datetime.now() - creation_date).days
                return age

        return 0

    except:
        return 0
