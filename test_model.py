import pandas as pd
import joblib

from extract_features import extract_features


# Load trained model
model = joblib.load("phishing_model_new.pkl")


# Test URLs
test_urls = [
    "https://www.google.com",
    "https://github.com",
    "https://www.microsoft.com",
    "http://110.37.26.193:54956/bin.sh",
    "https://login-verify-account.example.com/secure/login",
    "http://192.168.1.100/login.php?password=12345"
]


print("=" * 60)
print("LINKSHIELD ML MODEL TEST")
print("=" * 60)


for url in test_urls:

    # Extract features
    features = extract_features(url)

    # Convert to DataFrame
    features_df = pd.DataFrame([features])

    # Prediction
    prediction = model.predict(features_df)[0]

    # Probability
    probabilities = model.predict_proba(features_df)[0]

    phishing_probability = probabilities[1]

    if prediction == 1:
        result = "PHISHING"
    else:
        result = "LEGITIMATE"

    print("\nURL:", url)
    print("Prediction:", result)
    print(
        "Phishing Probability:",
        f"{phishing_probability * 100:.2f}%"
    )