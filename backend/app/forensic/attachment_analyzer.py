import hashlib
import mimetypes
from pathlib import Path


RISKY_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".hta",
    ".dll",
    ".jar",
    ".lnk",
    ".iso",
    ".img",
}


SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".bat",
    ".cmd",
    ".hta",
}


DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
}


def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def analyze_attachment(
    filename: str,
    content_type: str,
    data: bytes
) -> dict:

    path = Path(filename)

    extension = path.suffix.lower()

    mime_type = (
        content_type
        or mimetypes.guess_type(filename)[0]
    )

    if not mime_type:
        mime_type = "application/octet-stream"

    sha256 = calculate_sha256(data)

    indicators = []

    risky = False

    # --------------------------------------------------
    # 1. Dangerous extension
    # --------------------------------------------------

    if extension in RISKY_EXTENSIONS:

        risky = True

        indicators.append(
            f"Potentially dangerous file extension: {extension}"
        )

    # --------------------------------------------------
    # 2. Double extension detection
    # --------------------------------------------------

    filename_parts = [
        part.lower()
        for part in path.name.split(".")
    ]

    if len(filename_parts) >= 3:

        previous_extension = "." + filename_parts[-2]

        if (
            previous_extension in DOCUMENT_EXTENSIONS
            and extension in RISKY_EXTENSIONS
        ):

            risky = True

            indicators.append(
                "Double-extension filename may disguise "
                "a dangerous executable or script"
            )

    # --------------------------------------------------
    # 3. Suspicious script file
    # --------------------------------------------------

    if extension in SCRIPT_EXTENSIONS:

        risky = True

        indicators.append(
            "Attachment is a script file"
        )

    # --------------------------------------------------
    # 4. No extension
    # --------------------------------------------------

    if not extension:

        indicators.append(
            "Attachment has no file extension"
        )

    # --------------------------------------------------
    # 5. Empty attachment
    # --------------------------------------------------

    if len(data) == 0:

        indicators.append(
            "Attachment is empty"
        )

    # --------------------------------------------------
    # 6. MIME type mismatch
    # --------------------------------------------------

    guessed_mime = mimetypes.guess_type(filename)[0]

    if (
        guessed_mime
        and content_type
        and guessed_mime.lower()
        != content_type.lower()
    ):

        indicators.append(
            "Declared MIME type does not match "
            "the filename extension"
        )

    # --------------------------------------------------
    # 7. Suspicious filename keywords
    # --------------------------------------------------

    suspicious_keywords = [
        "invoice",
        "payment",
        "refund",
        "salary",
        "urgent",
        "verify",
        "account",
        "password",
        "security",
        "document",
    ]

    filename_lower = filename.lower()

    matched_keywords = []

    for keyword in suspicious_keywords:

        if keyword in filename_lower:

            matched_keywords.append(keyword)

    if matched_keywords:

        indicators.append(
            "Filename contains potentially social-engineering "
            f"keywords: {', '.join(matched_keywords)}"
        )

    # --------------------------------------------------
    # Final result
    # --------------------------------------------------

    return {
        "filename": filename,
        "extension": extension,
        "content_type": content_type,
        "detected_mime_type": mime_type,
        "size_bytes": len(data),
        "sha256": sha256,
        "risky": risky,
        "indicators": indicators
    }


def analyze_attachments(
    attachments: list
) -> list:

    results = []

    for attachment in attachments:

        filename = attachment.get(
            "filename",
            ""
        )

        content_type = attachment.get(
            "content_type",
            ""
        )

        data = attachment.get(
            "data",
            b""
        )

        result = analyze_attachment(
            filename=filename,
            content_type=content_type,
            data=data
        )

        results.append(result)

    return results