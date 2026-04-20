from flask import Flask, render_template, request
import joblib
import os
from urllib.parse import urlparse

from security_layer import (
    is_trusted_domain,
    is_suspicious_domain,
    is_brand_attack,
    has_credentials,
    extract_domain
)

app = Flask(__name__)

# Load ML model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "advanced_phishing_model.sav")

try:
    model = joblib.load(model_path)
except:
    model = None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]

    # Normalize URL
    if not url.startswith("http"):
        url = "https://" + url

    domain = extract_domain(url)

    # Default UI values
    dns = True
    ssl = True
    age = 5000
    ml_score = 0.0

    # ML prediction
    if model:
        try:
            features = [len(url), url.count("."), url.count("-")]
            ml_score = model.predict_proba([features])[0][1]
        except:
            ml_score = 0.5

    # 🔥 FINAL DETECTION LOGIC (CORRECT ORDER)

    if has_credentials(url):
        prediction_text = "🚨 Suspicious URL (Contains Credentials)"

    elif is_trusted_domain(domain):
        prediction_text = "✅ Legitimate Website (Trusted Domain)"

    elif is_brand_attack(domain):
        prediction_text = "🚨 Brand Impersonation (Phishing)"

    elif is_suspicious_domain(domain):
        prediction_text = "⚠️ Suspicious Website"

    else:
        if ml_score > 0.95:
            prediction_text = "🚨 Phishing Website Detected"
        elif ml_score > 0.6:
            prediction_text = "⚠️ Suspicious Website"
        else:
            prediction_text = "🟢 Legitimate Website"

    return render_template(
        "index.html",
        prediction_text=prediction_text,
        url=url,
        dns=dns,
        ssl=ssl,
        age=age,
        ml=round(ml_score, 2)
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
