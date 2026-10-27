"""Deterministic security signals used alongside the ML text classifier.

This module deliberately does not visit URLs or execute attachments.  It only
examines the supplied message locally, making it suitable for triage previews.
"""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from typing import Any
from urllib.parse import urlsplit


URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly",
}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "work", "support"}
URGENCY_TERMS = {
    "urgent", "immediately", "action required", "final notice", "suspended",
    "within 24 hours", "expire", "verify now", "limited time",
}
CREDENTIAL_TERMS = {
    "password", "credential", "sign in", "login", "verify your account",
    "security code", "one-time code", "mfa", "banking details",
}
PAYMENT_TERMS = {
    "wire transfer", "invoice", "payment", "gift card", "bitcoin", "cryptocurrency",
    "bank account", "refund",
}
BRANDS = {"microsoft", "google", "paypal", "amazon", "apple", "netflix", "linkedin", "docusign"}


def _domain(value: str) -> str:
    match = EMAIL_PATTERN.search(value or "")
    return match.group(1).lower().strip(".") if match else ""


def _signal(category: str, severity: str, title: str, evidence: str, points: int) -> dict[str, Any]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence[:220],
        "points": points,
    }


def parse_email(content: str) -> tuple[dict[str, str], str, Any]:
    """Parse RFC-822-like input but gracefully accept plain pasted text."""
    message = Parser(policy=policy.default).parsestr(content)
    headers = {
        "from": str(message.get("From", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "return_path": str(message.get("Return-Path", "")),
        "subject": str(message.get("Subject", "")),
        "authentication_results": str(message.get("Authentication-Results", "")),
    }
    try:
        body = message.get_body(preferencelist=("plain", "html"))
        text = body.get_content() if body else message.get_content()
    except (LookupError, TypeError, AttributeError):
        text = content
    return headers, str(text or content), message


def extract_security_signals(content: str) -> dict[str, Any]:
    headers, body, message = parse_email(content)
    combined = f"{headers['subject']}\n{body}".lower()
    signals: list[dict[str, Any]] = []

    from_domain = _domain(headers["from"])
    reply_domain = _domain(headers["reply_to"])
    return_domain = _domain(headers["return_path"])
    if from_domain and reply_domain and from_domain != reply_domain:
        signals.append(_signal("sender", "high", "Sender and reply-to domains differ", f"From: {from_domain}; Reply-To: {reply_domain}", 22))
    if from_domain and return_domain and from_domain != return_domain:
        signals.append(_signal("sender", "medium", "Return-path differs from sender", f"From: {from_domain}; Return-Path: {return_domain}", 10))

    auth = headers["authentication_results"].lower()
    for control in ("spf", "dkim", "dmarc"):
        if re.search(rf"{control}\s*=\s*(fail|softfail|neutral|none)", auth):
            signals.append(_signal("authentication", "high", f"{control.upper()} did not pass", headers["authentication_results"], 18))

    urls = []
    for raw_url in URL_PATTERN.findall(f"{headers['subject']}\n{body}"):
        candidate = raw_url.rstrip(".,;:!?)]}")
        normalized = candidate if candidate.lower().startswith("http") else f"https://{candidate}"
        parsed = urlsplit(normalized)
        host = (parsed.hostname or "").lower()
        urls.append({"display": candidate, "host": host})
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            signals.append(_signal("url", "high", "URL uses a direct IP address", candidate, 20))
        if host.startswith("xn--") or ".xn--" in host:
            signals.append(_signal("url", "high", "URL contains a punycode domain", candidate, 20))
        if host in SHORTENER_DOMAINS:
            signals.append(_signal("url", "medium", "Shortened URL obscures destination", candidate, 12))
        if host.split(".")[-1:] and host.split(".")[-1] in RISKY_TLDS:
            signals.append(_signal("url", "medium", "URL uses a high-risk top-level domain", candidate, 9))
        if "@" in parsed.netloc or len(candidate) > 150:
            signals.append(_signal("url", "medium", "URL has obfuscation characteristics", candidate, 10))

    for term in sorted(URGENCY_TERMS):
        if term in combined:
            signals.append(_signal("content", "medium", "Urgency or account-pressure language", term, 6))
            break
    for term in sorted(CREDENTIAL_TERMS):
        if term in combined:
            signals.append(_signal("content", "high", "Credential or account-verification request", term, 12))
            break
    for term in sorted(PAYMENT_TERMS):
        if term in combined:
            signals.append(_signal("content", "high", "Payment or financial-transfer request", term, 12))
            break
    for brand in sorted(BRANDS):
        if brand in combined and from_domain and brand not in from_domain:
            signals.append(_signal("impersonation", "medium", "Possible brand impersonation", f"Brand reference: {brand}; sender: {from_domain}", 9))
            break

    attachment_count = 0
    suspicious_attachments = []
    if message.is_multipart():
        for part in message.iter_attachments():
            attachment_count += 1
            filename = str(part.get_filename() or "unnamed attachment")
            if filename.lower().endswith((".exe", ".js", ".vbs", ".bat", ".scr", ".iso", ".zip", ".html")):
                suspicious_attachments.append(filename)
                signals.append(_signal("attachment", "high", "Potentially risky attachment type", filename, 16))

    # Cap deterministic risk so a repetitive body cannot inflate a score forever.
    deterministic_score = min(100, sum(item["points"] for item in signals))
    return {
        "headers": headers,
        "urls": urls[:20],
        "attachment_count": attachment_count,
        "suspicious_attachments": suspicious_attachments[:10],
        "signals": signals[:20],
        "deterministic_score": deterministic_score,
    }


def severity_for(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def recommended_actions(severity: str) -> list[str]:
    actions = {
        "critical": ["Do not open links or attachments.", "Report and quarantine the message for security review.", "Reset exposed credentials from a trusted device if interaction occurred."],
        "high": ["Do not reply or provide credentials.", "Verify the request through a known contact channel.", "Report the message to the security team."],
        "medium": ["Independently verify the sender and destination URLs.", "Avoid using links in the message; navigate to the service directly.", "Escalate if the request is unexpected."],
        "low": ["No high-risk indicators were found.", "Remain cautious: analysis is advisory and cannot guarantee safety."],
    }
    return actions[severity]
