from flask import Flask, render_template, request
import joblib
from urllib.parse import urlparse
from difflib import SequenceMatcher

from advanced_feature_extraction import FeatureExtraction
from security_layer import (
    extract_domain,
    has_dns,
    has_ssl,
    get_domain_age,
    is_trusted_domain
)

app = Flask(__name__)

model = joblib.load("advanced_phishing_model.sav")

# 🔥 BRAND LIST
KNOWN_BRANDS = [
    "google", "facebook", "instagram",
    "yahoo", "amazon", "twitter",
    "linkedin", "netflix", "microsoft"
]


# 🔥 URL NORMALIZATION
def normalize_url(url):
    url = url.strip()

    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if not domain.startswith("www."):
        domain = "www." + domain

    return "https://" + domain


# 🔥 DOMAIN TEXT NORMALIZATION
def normalize_domain_text(domain):
    domain = domain.lower().replace("www.", "")

    replacements = {
        '0': '0',
        '1': 'l',
        '3': 'e',
        '5': 's',
        '7': 't'
    }

    for k, v in replacements.items():
        domain = domain.replace(k, v)

    return domain


# 🔥 FIXED TYPOSQUATTING DETECTION
def is_typosquatting(domain):
    clean = normalize_domain_text(domain)

    for brand in KNOWN_BRANDS:

        # Skip exact match
        if clean == brand:
            continue

        similarity = SequenceMatcher(None, clean, brand).ratio()

        if similarity > 0.80:
            return True

    return False


# 🔥 MULTI BRAND DETECTION
def multiple_brand_check(domain):
    clean = normalize_domain_text(domain)

    count = sum(1 for brand in KNOWN_BRANDS if brand in clean)

    return count >= 2


# 🔥 SUSPICIOUS PATTERN CHECK
def suspicious_pattern(domain):
    digit_count = sum(c.isdigit() for c in domain)
    hyphen_count = domain.count("-")

    return digit_count >= 3 or hyphen_count >= 2


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/predict', methods=['POST'])
def predict():

    url = request.form['url']
    url = normalize_url(url)

    domain = extract_domain(url)

    # 🔍 SECURITY CHECKS
    dns_check = has_dns(domain)
    ssl_check = has_ssl(domain)
    domain_age = get_domain_age(domain)

    # 🧠 ML
    features = FeatureExtraction(url).get_features()
    proba = model.predict_proba([features])[0]
    phishing_prob = proba[1]

    # 🎯 SCORE
    score = 0

    if not dns_check:
        score += 2

    if not ssl_check:
        score += 1

    if domain_age != 0 and domain_age < 180:
        score += 2

    if phishing_prob > 0.7:
        score += 3

    if is_typosquatting(domain):
        score += 4

    if multiple_brand_check(domain):
        score += 4

    if suspicious_pattern(domain):
        score += 1

    # 🔥 FINAL DECISION (CORRECT ORDER)

    if is_trusted_domain(domain):
        result = "✅ Legitimate Website (Trusted Domain)"

    elif multiple_brand_check(domain):
        result = "🚨 Phishing (Multiple Brand Impersonation)"

    elif is_typosquatting(domain):
        result = "🚨 Phishing (Brand Impersonation)"

    elif phishing_prob > 0.9:
        result = "⚠️ Phishing Website Detected"

    elif score >= 6:
        result = "🔴 Dangerous Website"

    elif score >= 3:
        result = "🟡 Suspicious Website"

    else:
        result = "🟢 Legitimate Website"

    # Debug
    print("\n--- DEBUG ---")
    print("URL:", url)
    print("Domain:", domain)
    print("Score:", score)
    print("Phishing Prob:", phishing_prob)

    return render_template(
        "index.html",
        prediction_text=result,
        url=url,
        dns=dns_check,
        ssl=ssl_check,
        age=domain_age,
        ml=round(phishing_prob, 2),
        score=score
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
