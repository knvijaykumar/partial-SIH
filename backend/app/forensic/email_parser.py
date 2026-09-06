from email import policy
from email.parser import BytesParser
from email.message import Message
from bs4 import BeautifulSoup
import re


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def extract_body(message: Message):
    plain_text = ""
    html_text = ""

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    plain_text += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_text += part.get_content()
                except Exception:
                    pass

    else:
        content_type = message.get_content_type()

        try:
            if content_type == "text/plain":
                plain_text = message.get_content()

            elif content_type == "text/html":
                html_text = message.get_content()

        except Exception:
            pass

    if html_text:
        soup = BeautifulSoup(
            html_text,
            "html.parser"
        )

        html_text = soup.get_text(
            " ",
            strip=True
        )

    return {
        "plain_text": plain_text.strip(),
        "html_text": html_text.strip()
    }


def extract_urls(body):
    urls = URL_PATTERN.findall(body)

    return list(
        dict.fromkeys(urls)
    )


def extract_attachments(message: Message):

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if filename:

            payload = (
                part.get_payload(
                    decode=True
                )
                or b""
            )

            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "data": payload
            })

    return attachments


def extract_headers(message: Message):

    authentication_results = message.get(
        "Authentication-Results",
        ""
    )

    received_headers = message.get_all(
        "Received",
        []
    )

    return {
        "subject": message.get("Subject"),
        "from": message.get("From"),
        "to": message.get("To"),
        "date": message.get("Date"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "message_id": message.get("Message-ID"),
        "received": received_headers,
        "authentication_results": authentication_results
    }


def extract_authentication_status(
    authentication_results
):

    text = authentication_results.lower()

    spf = "unknown"
    dkim = "unknown"
    dmarc = "unknown"

    spf_match = re.search(
        r"\bspf\s*=\s*"
        r"(pass|fail|softfail|neutral|none|"
        r"temperror|permerror)",
        text
    )

    dkim_match = re.search(
        r"\bdkim\s*=\s*"
        r"(pass|fail|neutral|none|"
        r"temperror|permerror)",
        text
    )

    dmarc_match = re.search(
        r"\bdmarc\s*=\s*"
        r"(pass|fail|bestguesspass|none|"
        r"temperror|permerror)",
        text
    )

    if spf_match:
        spf = spf_match.group(1)

    if dkim_match:
        dkim = dkim_match.group(1)

    if dmarc_match:
        dmarc = dmarc_match.group(1)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }


def parse_email(file_path: str):

    with open(
        file_path,
        "rb"
    ) as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)

    headers = extract_headers(message)

    body = extract_body(message)

    combined_body = (
        body["plain_text"]
        + " "
        + body["html_text"]
    )

    urls = extract_urls(
        combined_body
    )

    attachments = extract_attachments(
        message
    )

    authentication = (
        extract_authentication_status(
            headers[
                "authentication_results"
            ]
        )
    )

    return {
        "headers": headers,
        "authentication": authentication,
        "body": body,
        "urls": urls,
        "attachments": attachments
    }