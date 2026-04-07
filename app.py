from flask import Flask, render_template, request
import joblib
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


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']

    # 🔥 Normalize URL safely
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    domain_part = url.split("//")[1]

    if not domain_part.startswith("www."):
        url = url.replace("https://", "https://www.")

    domain = extract_domain(url)

    # 🔍 Security checks
    dns_check = has_dns(domain)
    ssl_check = has_ssl(domain)
    domain_age = get_domain_age(domain)

    # 🧠 ML prediction
    features = FeatureExtraction(url).get_features()
    proba = model.predict_proba([features])[0]
    phishing_prob = proba[1]

    # 🎯 Score
    score = 0

    if not dns_check:
        score += 2

    if not ssl_check:
        score += 1

    if domain_age != 0 and domain_age < 180:
        score += 2

    if phishing_prob > 0.7:
        score += 3

    # 🔥 FINAL LOGIC
    if is_trusted_domain(domain):
        result = "✅ Legitimate Website (Trusted Domain)"

    elif phishing_prob > 0.9:
        result = "⚠️ Phishing Website Detected"

    elif dns_check and ssl_check and (domain_age == 0 or domain_age > 180):

        if phishing_prob < 0.6:
            result = "✅ Legitimate Website"
        else:
            result = "⚠️ Suspicious Website"

    else:
        result = "⚠️ Suspicious Website"

    # Debug
    print("\n--- DEBUG ---")
    print("URL:", url)
    print("Domain:", domain)
    print("DNS:", dns_check)
    print("SSL:", ssl_check)
    print("Age:", domain_age)
    print("Phishing Prob:", phishing_prob)
    print("Score:", score)

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
