from transformers import pipeline


MODEL_NAME = "specific-AI/email-agent-phishing-detection"


classifier = pipeline(
    "text-classification",
    model=MODEL_NAME,
    tokenizer=MODEL_NAME
)


def predict_phishing(
    sender: str,
    subject: str,
    body: str
):
    text = f"""
From: {sender}
Subject: {subject}

{body}
"""

    result = classifier(text)[0]

    return {
        "label": result["label"],
        "score": round(float(result["score"]), 4)
    }