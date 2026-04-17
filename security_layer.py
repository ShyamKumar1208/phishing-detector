import tldextract

# 🔥 Trusted domains
TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "instagram.com",
    "amazon.com", "youtube.com", "yahoo.com",
    "microsoft.com", "linkedin.com",
    "dituniversity.edu.in"
]


def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"


# 🔥 Trusted check
def is_trusted_domain(url):
    domain = extract_domain(url)

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True

    return False


# 🔥 Simple brand check (optional)
def is_suspicious_domain(url):
    suspicious_keywords = ["login", "secure", "verify", "update"]

    for word in suspicious_keywords:
        if word in url.lower():
            return True

    return False
