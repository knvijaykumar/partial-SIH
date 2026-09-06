from app.forensic.attachment_analyzer import analyze_attachment


def main():
    # Safe fake attachment data
    test_data = b"This is a harmless test attachment for SIH26106."

    result = analyze_attachment(
        filename="document.pdf",
        content_type="application/octet-stream",
        data=test_data
    )

    print("\n========== ATTACHMENT FORENSICS TEST ==========")

    for key, value in result.items():
        print(f"{key}: {value}")

    print("===============================================")


if __name__ == "__main__":
    main()