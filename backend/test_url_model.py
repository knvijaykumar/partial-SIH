from transformers import pipeline

MODEL_NAME = "najlajj453/malicious-url-distilbert"

classifier = pipeline(
    "text-classification",
    model=MODEL_NAME,
    tokenizer=MODEL_NAME
)

test_urls = [
    "https://www.google.com",
    "http://paypal-login-verify-account.example.com"
]

for url in test_urls:
    result = classifier(url)[0]

    print("\nURL:", url)
    print("Prediction:", result["label"])
    print("Confidence:", round(float(result["score"]), 4))