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


# 🔥 Normalize characters (0 → o etc.)
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


# 🔥 Extract clean domain (handles @ attack)
def extract_domain(url):
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    netloc = parsed.netloc

    # remove credentials (user@)
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    return netloc.replace("www.", "")


# 🔥 Split domain name
def split_domain(domain):
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


# 🔥 Credential attack detection
def has_credentials(url):
    return "@" in url


# 🔥 Trusted domain check
def is_trusted_domain(domain):
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


# 🔥 Brand impersonation detection
def is_brand_attack(domain):
    name = split_domain(domain)

    original = name.lower()
    clean = normalize(original)

    for brand in KNOWN_BRANDS:

        # Legit
        if original == brand:
            continue

        # 🚨 g00gle → google
        if clean == brand and original != brand:
            return True

        # 🚨 gooogle / faceb00k
        if brand in clean and clean != brand:
            return True

    return False


# 🔥 Basic suspicious keywords
def is_suspicious_domain(domain):
    keywords = ["login", "secure", "verify", "update", "bank"]

    domain = domain.lower()

    for word in keywords:
        if word in domain:
            return True

    return False
