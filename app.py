from flask import Flask, render_template, request
import joblib
from urllib.parse import urlparse
from difflib import SequenceMatcher
import requests

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
    "google.com", "facebook.com", "instagram.com",
    "yahoo.com", "amazon.com", "twitter.com",
    "linkedin.com", "netflix.com"
]

# 🔥 URL NORMALIZATION
def normalize_url(url):
    url = url.strip()

    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www.www."):
        domain = domain.replace("www.www.", "www.")

    if not domain.startswith("www."):
        domain = "www." + domain

    return "https://" + domain


# 🔥 BRAND SIMILARITY CHECK
def is_typosquatting(domain):
    domain = domain.replace("www.", "")

    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if similarity > 0.85 and domain != brand:
            return True

    return False


# 🔥 CHARACTER ANALYSIS
def suspicious_pattern(domain):
    digit_count = sum(c.isdigit() for c in domain)
    return digit_count > 2


# 🔥 GOOGLE SAFE BROWSING (OPTIONAL PLACEHOLDER)
def check_threat_api(url):
    # (You can integrate real API later)
    return False


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/predict', methods=['POST'])
def predict():

    url = request.form['url']
    url = normalize_url(url)

    domain = extract_domain(url).lower()

    # 🔍 Security Checks
    dns_check = has_dns(domain)
    ssl_check = has_ssl(domain)
    domain_age = get_domain_age(domain)

    # 🧠 ML Prediction
    features = FeatureExtraction(url).get_features()
    proba = model.predict_proba([features])[0]
    phishing_prob = proba[1]

    # 🎯 Score
    score = 0

    # Layer 1: DNS / SSL
    if not dns_check:
        score += 2
    if not ssl_check:
        score += 1

    # Layer 2: Domain Age
    if domain_age != 0 and domain_age < 180:
        score += 2

    # Layer 3: ML
    if phishing_prob > 0.7:
        score += 3

    # 🔥 NEW LAYER: BRAND INTELLIGENCE
    if is_typosquatting(domain):
        score += 4

    # 🔥 NEW LAYER: PATTERN CHECK
    if suspicious_pattern(domain):
        score += 1

    # 🔥 NEW LAYER: THREAT API
    if check_threat_api(url):
        return render_template("index.html",
            prediction_text="🚨 Blacklisted Phishing Website",
            url=url, dns=dns_check, ssl=ssl_check,
            age=domain_age, ml=round(phishing_prob,2), score=5
        )

    # 🔥 FINAL DECISION ENGINE
    if is_trusted_domain(domain):
        result = "✅ Legitimate Website (Trusted Domain)"

    elif is_typosquatting(domain):
        result = "🚨 Phishing (Brand Impersonation Detected)"

    elif phishing_prob > 0.9:
        result = "⚠️ Phishing Website Detected"

    elif score >= 5:
        result = "⚠️ High Risk Website"

    elif score >= 3:
        result = "⚠️ Suspicious Website"

    else:
        result = "✅ Legitimate Website"

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
