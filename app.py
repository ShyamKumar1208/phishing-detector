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

# 🔥 BRAND DATABASE
KNOWN_BRANDS = [
    "google", "facebook", "instagram",
    "yahoo", "amazon", "twitter",
    "linkedin", "netflix", "microsoft"
]

# 🔥 CHARACTER NORMALIZATION (IMPORTANT)
def normalize_domain_text(domain):
    domain = domain.lower().replace("www.", "")

    replacements = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '5': 's',
        '7': 't',
        '@': 'a'
    }

    for k, v in replacements.items():
        domain = domain.replace(k, v)

    return domain


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


# 🔥 ADVANCED TYPOSQUATTING DETECTION
def is_typosquatting(domain):
    clean = normalize_domain_text(domain)

    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, clean, brand).ratio()

        # Direct substring (google-login, etc.)
        if brand in clean and clean != brand:
            return True

        # Similarity match
        if similarity > 0.75 and clean != brand:
            return True

    return False


# 🔥 MULTI BRAND DETECTION (VERY IMPORTANT)
def multiple_brand_check(domain):
    clean = normalize_domain_text(domain)

    count = sum(1 for brand in KNOWN_BRANDS if brand in clean)
    return count >= 2


# 🔥 SUSPICIOUS PATTERN CHECK
def suspicious_pattern(domain):
    domain = domain.lower()

    digit_count = sum(c.isdigit() for c in domain)
    hyphen_count = domain.count("-")

    if digit_count >= 2:
        return True

    if hyphen_count >= 2:
        return True

    return False


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

    # 🔥 ADVANCED DETECTION LAYERS
    if is_typosquatting(domain):
        score += 4

    if multiple_brand_check(domain):
        score += 4

    if suspicious_pattern(domain):
        score += 2

    # 🔥 FINAL DECISION ENGINE
    if multiple_brand_check(domain):
        result = "🚨 Phishing (Multiple Brand Impersonation)"

    elif is_typosquatting(domain):
        result = "🚨 Phishing (Brand Impersonation)"

    elif phishing_prob > 0.9:
        result = "⚠️ Phishing Website Detected"

    elif is_trusted_domain(domain):
        result = "✅ Legitimate Website (Trusted Domain)"

    elif score >= 6:
        result = "🔴 Dangerous Website"

    elif score >= 3:
        result = "🟡 Suspicious Website"

    else:
        result = "🟢 Legitimate Website"

    # DEBUG
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
