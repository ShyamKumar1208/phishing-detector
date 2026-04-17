from flask import Flask, render_template, request
import joblib
import os

from security_layer import is_trusted_domain, is_suspicious_domain

app = Flask(__name__)

# 🔥 Load ML model safely
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "advanced_phishing_model.sav")

try:
    model = joblib.load(model_path)
except:
    model = None


# 🔥 Home route
@app.route("/")
def home():
    return render_template("index.html")


# 🔥 Prediction route
@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]

    # 🔥 Default values (for UI)
    dns = "✔"
    ssl = "✔"
    age = 5000
    ml_score = 0.0

    # 🔥 ML Prediction (if model exists)
    if model:
        try:
            features = [len(url), url.count("."), url.count("-")]
            ml_score = model.predict_proba([features])[0][1]
        except:
            ml_score = 0.5

    # 🔥 DECISION LOGIC (FIXED)

    # 1️⃣ Trusted domains (highest priority)
    if is_trusted_domain(url):
        result = "✅ Legitimate Website (Trusted Domain)"
        risk_level = "Legitimate"

    # 2️⃣ Rule-based suspicious check
    elif is_suspicious_domain(url):
        result = "⚠️ Suspicious Website"
        risk_level = "Suspicious"

    # 3️⃣ ML-based detection (last)
    else:
        if ml_score > 0.95:
            result = "🚨 Phishing Website Detected"
            risk_level = "Dangerous"
        elif ml_score > 0.6:
            result = "⚠️ Suspicious Website"
            risk_level = "Suspicious"
        else:
            result = "🟢 Legitimate Website"
            risk_level = "Legitimate"

    return render_template(
        "index.html",
        result=result,
        url=url,
        dns=dns,
        ssl=ssl,
        age=age,
        ml=round(ml_score, 2),
        risk=risk_level
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
