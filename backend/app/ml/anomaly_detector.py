from sklearn.ensemble import IsolationForest


FEATURE_NAMES = [
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "reply_to_mismatch",
    "received_count",
    "url_count",
    "suspicious_url_count",
    "attachment_count",
    "risky_attachment_count",
    "urgency_count",
    "credential_count",
    "financial_count",
    "body_length",
]


def _build_feature_vector(features: dict) -> list:
    """
    Convert extracted email features into a numerical vector.
    Missing features are safely treated as zero.
    """

    return [
        float(features.get(name, 0) or 0)
        for name in FEATURE_NAMES
    ]


def detect_anomaly(features: dict) -> dict:
    """
    Detect unusual email characteristics using Isolation Forest.

    This is an initial MVP anomaly-detection baseline.
    A production system should train the detector using
    a representative dataset of legitimate organizational emails.
    """

    feature_vector = _build_feature_vector(features)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42
    )

    # Initial baseline:
    # Isolation Forest normally requires a representative
    # dataset. For this MVP, we construct a small reference
    # population around the current feature vector.
    reference_vectors = [
        [0.0] * len(FEATURE_NAMES),
        [0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 100.0],
        [0.0, 0.0, 0.0, 0.0, 2.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 500.0],
        [0.0, 0.0, 0.0, 0.0, 3.0, 2.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 1000.0],
        [0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 300.0],
        [1.0, 0.0, 0.0, 1.0, 5.0, 3.0, 2.0, 1.0, 0.0, 3.0, 2.0, 1.0, 2000.0],
        [0.0, 1.0, 1.0, 1.0, 6.0, 4.0, 3.0, 1.0, 1.0, 4.0, 3.0, 2.0, 3000.0],
        [1.0, 1.0, 1.0, 1.0, 8.0, 5.0, 4.0, 2.0, 2.0, 5.0, 4.0, 3.0, 5000.0],
        [0.0, 0.0, 0.0, 0.0, 2.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 800.0],
        [1.0, 0.0, 0.0, 1.0, 4.0, 2.0, 1.0, 1.0, 0.0, 2.0, 2.0, 1.0, 1500.0],
    ]

    model.fit(reference_vectors)

    prediction = model.predict([feature_vector])[0]
    raw_score = float(model.decision_function([feature_vector])[0])

    is_anomaly = prediction == -1

    # Convert the Isolation Forest score into an easy-to-read
    # anomaly score. This is a relative MVP score, not a probability.
    anomaly_score = max(
        0.0,
        min(
            100.0,
            50.0 - (raw_score * 100.0)
        )
    )

    if is_anomaly:
        explanation = (
            "The email contains an unusual combination of "
            "technical or behavioral features compared with "
            "the current baseline."
        )
    else:
        explanation = (
            "The email's extracted features are not significantly "
            "unusual compared with the current baseline."
        )

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": round(anomaly_score, 2),
        "explanation": explanation,
        "method": "Isolation Forest"
    }