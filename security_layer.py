import dns.resolver
import ssl
import socket
import requests
from datetime import datetime


# 🔥 TRUSTED DOMAINS (EXTENDED LIST)
TRUSTED_DOMAINS = [

    # Search
    "google.com", "bing.com", "yahoo.com",

    # Social
    "instagram.com", "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "snapchat.com", "reddit.com",

    # Media
    "youtube.com", "netflix.com", "primevideo.com",
    "hotstar.com", "spotify.com",

    # Shopping
    "amazon.com", "amazon.in", "flipkart.com", "myntra.com",
    "ajio.com", "meesho.com",

    # Payments / Banking
    "paytm.com", "phonepe.com", "upi.com",
    "icicibank.com", "hdfcbank.com", "sbi.co.in", "axisbank.com",

    # Email / Cloud
    "gmail.com", "outlook.com", "icloud.com",
    "drive.google.com", "dropbox.com",

    # Dev / Learning
    "github.com", "stackoverflow.com", "kaggle.com",
    "geeksforgeeks.org", "w3schools.com",

    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",

    # 🔥 YOUR UNIVERSITY
    "dituniversity.edu.in",
    "diterp.dituniversity.edu.in",

    # Government
    "gov.in", "nic.in", "uidai.gov.in", "income-tax.gov.in",

    # Travel
    "irctc.co.in", "makemytrip.com", "goibibo.com",

    # News
    "timesofindia.com", "ndtv.com", "bbc.com", "hindustantimes.com"
]


def is_trusted_domain(domain):
    return any(site in domain for site in TRUSTED_DOMAINS)


# Extract domain
def extract_domain(url):
    domain = url.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    return domain


# DNS check
def has_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False


# SSL check (robust)
def has_ssl(domain):
    try:
        ctx = ssl.create_default_context()

        # Try normal
        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    return True
        except:
            pass

        # Try www
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