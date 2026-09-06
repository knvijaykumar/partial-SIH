"""
Evaluation and Test Script for CrabInHoney/urlbert-tiny-v4-malicious-url-classifier
Tests benign URLs, phishing-style URLs, IP URLs, subdomains, long paths, query params, etc.
Includes scheme vs non-scheme comparison and max-length truncation handling.
"""
import sys
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

MODEL_NAME = "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"

LABEL_MAPPING = {
    "LABEL_0": "benign",
    "LABEL_1": "defacement",
    "LABEL_2": "malware",
    "LABEL_3": "phishing"
}


def load_model_pipeline():
    print(f"Loading model and tokenizer from '{MODEL_NAME}'...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, model_max_length=64, truncation=True)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    
    classifier = pipeline(
        "text-classification",
        model=model,
        tokenizer=tokenizer,
        truncation=True,
        max_length=64,
        top_k=None  # Return all class probabilities
    )
    return classifier


def evaluate_urls(classifier):
    # 1. Required Benign URLs
    benign_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://github.com",
        "https://www.wikipedia.org",
        "https://www.example.com",
    ]

    # 2. Required Suspicious / Phishing-style URLs
    suspicious_urls = [
        "http://paypal-login-verify.example.com",
        "http://account-security-update.example.com/login",
        "http://secure-login-verify.example.com",
        "http://bank-account-verification.example.com",
        "http://microsoft-login-security.example.com",
    ]

    # 3. Additional Diverse Feature URLs
    additional_urls = [
        ("https://accounts.google.com/signin", "Benign (HTTPS + sensitive keywords on legitimate platform)"),
        ("https://docs.python.org/3/library/urllib.parse.html", "Benign (HTTPS + long documentation path)"),
        ("https://paypal-security-verification.com/login", "Malicious/Phishing (HTTPS + brand spoofing)"),
        ("http://info.cern.ch/hypertext/WWW/TheProject.html", "Benign (HTTP legacy documentation)"),
        ("http://malware-drop-site.com/payload.exe", "Malicious/Malware (HTTP + executable payload)"),
        ("http://192.168.1.1/login", "Ambiguous/Private IP router login"),
        ("http://203.0.113.25/admin/login.php", "Suspicious/Public IP login"),
        ("http://login.verify.account.update.security-alert.evil.com", "Malicious/Phishing (Excessive subdomains)"),
        ("https://www.amazon.com/gp/product/B08N5WRWNW?ref=ppx_pt2_dt_b_prod_image&th=1", "Benign (Query parameters + deep path)"),
        ("http://fake-bank-update.test/auth?token=9382103981093810238120398&user=admin", "Malicious/Phishing (Query params + fake bank)"),
        ("http://defaced-website-sample.org/index.html", "Malicious/Defacement sample"),
    ]

    results_summary = []

    print("\n" + "="*80)
    print(" 1. EVALUATING REQUIRED BENIGN URLS (Full URL)")
    print("="*80)
    
    benign_predictions = []
    for url in benign_urls:
        res = classify_and_print(classifier, url, category="Benign")
        benign_predictions.append(res)
        results_summary.append(res)

    print("\n" + "="*80)
    print(" 2. EVALUATING REQUIRED SUSPICIOUS / PHISHING URLS (Full URL)")
    print("="*80)
    
    suspicious_predictions = []
    for url in suspicious_urls:
        res = classify_and_print(classifier, url, category="Suspicious/Phishing")
        suspicious_predictions.append(res)
        results_summary.append(res)

    print("\n" + "="*80)
    print(" 3. EVALUATING ADDITIONAL FEATURE URLS (HTTPS, HTTP, IP, SUBDOMAINS, PATHS, QUERIES)")
    print("="*80)
    
    additional_predictions = []
    for url, desc in additional_urls:
        res = classify_and_print(classifier, url, category=desc)
        additional_predictions.append(res)
        results_summary.append(res)

    print("\n" + "="*80)
    print(" 4. EVALUATING BENIGN URLS WITHOUT SCHEME PREFIX (e.g. 'google.com', 'wikipedia.org')")
    print("="*80)
    stripped_benign_urls = [
        "google.com",
        "www.google.com",
        "microsoft.com",
        "github.com",
        "wikipedia.org",
        "example.com",
        "wikiobits.com/Obits/TonyProudfoot"
    ]
    for url in stripped_benign_urls:
        classify_and_print(classifier, url, category="Benign (Scheme Stripped)")

    # Calculate statistics
    print("\n" + "="*80)
    print(" SUMMARY STATISTICS & ACCURACY METRICS")
    print("="*80)

    # Benign URLs accuracy
    benign_false_positives = [r for r in benign_predictions if r["is_malicious"]]
    print(f"Required Benign URLs: {len(benign_predictions)}")
    print(f" - Correctly Classified as Benign: {len(benign_predictions) - len(benign_false_positives)}/{len(benign_predictions)}")
    print(f" - False Positives (Benign misclassified as Malicious): {len(benign_false_positives)} ({len(benign_false_positives)/len(benign_predictions)*100:.1f}%)")
    for fp in benign_false_positives:
        print(f"   * {fp['url']} -> {fp['predicted_class']} ({fp['confidence']*100:.2f}%)")

    # Suspicious URLs accuracy
    suspicious_false_negatives = [r for r in suspicious_predictions if not r["is_malicious"]]
    print(f"\nRequired Suspicious URLs: {len(suspicious_predictions)}")
    print(f" - Correctly Classified as Malicious: {len(suspicious_predictions) - len(suspicious_false_negatives)}/{len(suspicious_predictions)}")
    print(f" - False Negatives (Suspicious misclassified as Benign): {len(suspicious_false_negatives)}")
    for fn in suspicious_false_negatives:
        print(f"   * {fn['url']} -> {fn['predicted_class']} ({fn['confidence']*100:.2f}%)")

    # Overall confidence
    all_confidences = [r["confidence"] for r in results_summary]
    avg_confidence = sum(all_confidences) / len(all_confidences)
    print(f"\nAverage Model Confidence across all test URLs: {avg_confidence*100:.2f}%")


def classify_and_print(classifier, url: str, category: str = ""):
    raw_results = classifier(url)[0]
    
    # Sort by probability descending
    sorted_probs = sorted(raw_results, key=lambda x: x["score"], reverse=True)
    top_result = sorted_probs[0]
    
    raw_label = top_result["label"]
    confidence = float(top_result["score"])
    predicted_class = LABEL_MAPPING.get(raw_label, raw_label)
    
    is_malicious = predicted_class != "benign"
    binary_verdict = "MALICIOUS" if is_malicious else "BENIGN"

    print(f"\nURL: {url}")
    if category:
        print(f"Category: {category}")
    print(f"Predicted Label: {predicted_class} (raw: {raw_label})")
    print(f"Confidence / Probability: {confidence * 100:.2f}%")
    print(f"Binary Assessment: {binary_verdict}")
    
    prob_dist_str = ", ".join([f"{LABEL_MAPPING.get(p['label'], p['label'])}: {p['score']*100:.2f}%" for p in sorted_probs])
    print(f"Full Distribution: [{prob_dist_str}]")

    return {
        "url": url,
        "category": category,
        "raw_label": raw_label,
        "predicted_class": predicted_class,
        "confidence": confidence,
        "is_malicious": is_malicious,
        "binary_verdict": binary_verdict,
        "distribution": sorted_probs
    }


if __name__ == "__main__":
    try:
        classifier = load_model_pipeline()
        evaluate_urls(classifier)
    except Exception as e:
        print(f"ERROR: Failed to run evaluation: {e}", file=sys.stderr)
        sys.exit(1)
