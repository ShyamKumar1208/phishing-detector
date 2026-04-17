from security_layer import is_trusted_domain, is_suspicious_domain, is_brand_attack

# 🔥 FINAL LOGIC
if is_trusted_domain(url):
    prediction_text = "✅ Legitimate Website (Trusted Domain)"

elif is_brand_attack(url):
    prediction_text = "🚨 Brand Impersonation (Phishing)"

elif is_suspicious_domain(url):
    prediction_text = "⚠️ Suspicious Website"

else:
    if ml_score > 0.95:
        prediction_text = "🚨 Phishing Website Detected"
    elif ml_score > 0.6:
        prediction_text = "⚠️ Suspicious Website"
    else:
        prediction_text = "🟢 Legitimate Website"
