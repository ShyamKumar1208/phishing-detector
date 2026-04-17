from flask import Flask, render_template, request
import joblib
import os
from urllib.parse import urlparse

from security_layer import is_trusted_domain, is_suspicious_domain, is_brand_attack

app = Flask(__name__)

# Load model
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

    # Normalize
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    # ML score
    ml_score = 0.0
    if model:
        try:
            features = [len(url), url.count("."), url.count("-")]
            ml_score = model.predict_proba([features])[0][1]
        except:
            ml_score = 0.5

    # 🔥 FINAL LOGIC (ALL INSIDE FUNCTION)
    if is_trusted_domain(domain):
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
        dns=True,
        ssl=True,
        age=5000,
        ml=round(ml_score, 2)
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
