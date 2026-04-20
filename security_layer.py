from urllib.parse import urlparse
import requests

GOOGLE_API_KEY = "AIzaSyD-pANdKxZyrpUMKd6HvmR2doY73NF0J_c"

def google_safe_check(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        result = response.json()

        if "matches" in result:
            return True  # 🚨 dangerous
    except:
        pass

    return False  # safe
# 🔥 Trusted domains
TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "instagram.com",
    "amazon.com", "youtube.com", "yahoo.com",
    "microsoft.com", "linkedin.com",
    "dituniversity.edu.in"
]

# 🔥 Known brands
KNOWN_BRANDS = [
    "google", "facebook", "instagram",
    "amazon", "yahoo", "microsoft",
    "netflix", "linkedin", "paypal", "apple"
]

VALID_TLDS = ["com", "org", "net", "in", "edu", "gov", "co"]


def normalize(text):
    replacements = {
        '0': 'o', '1': 'l', '3': 'e',
        '5': 's', '7': 't', '@': 'a'
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text


# 🔥 Extract domain safely
def extract_domain(url):
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    netloc = parsed.netloc

    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    return netloc.replace("www.", "")


# 🔥 INVALID URL CHECK (NEW)
def is_invalid_domain(domain):
    if "." not in domain:
        return True

    parts = domain.split(".")
    tld = parts[-1]

    if tld not in VALID_TLDS:
        return True

    return False


def split_domain(domain):
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


def has_credentials(url):
    return "@" in url


def is_trusted_domain(domain):
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


def is_brand_attack(domain):
    name = split_domain(domain)

    original = name.lower()
    clean = normalize(original)

    for brand in KNOWN_BRANDS:

        if original == brand:
            continue

        if clean == brand and original != brand:
            return True

        if brand in clean and clean != brand:
            return True

    return False


def is_suspicious_domain(domain):
    keywords = ["login", "secure", "verify", "update", "bank"]

    domain = domain.lower()

    for word in keywords:
        if word in domain:
            return True

    return False
