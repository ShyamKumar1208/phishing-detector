from urllib.parse import urlparse

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


def normalize(text):
    replacements = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '5': 's',
        '7': 't',
        '@': 'a'
    }

    for k, v in replacements.items():
        text = text.replace(k, v)

    return text


def extract_domain(url):
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    return parsed.netloc.replace("www.", "")


def split_domain(domain):
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


def is_trusted_domain(url):
    domain = extract_domain(url)

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True

    return False


# 🔥 NEW: BRAND ATTACK DETECTION
def is_brand_attack(url):
    domain = extract_domain(url)
    name = split_domain(domain)

    original = name.lower()
    clean = normalize(original)

    for brand in KNOWN_BRANDS:

        # Legit
        if original == brand:
            return False

        # 🚨 g00gle → google
        if clean == brand and original != brand:
            return True

        # 🚨 similarity (gooogle)
        if brand in clean and clean != brand:
            return True

    return False


def is_suspicious_domain(url):
    keywords = ["login", "secure", "verify", "update", "bank"]

    url = url.lower()

    for word in keywords:
        if word in url:
            return True

    return False
