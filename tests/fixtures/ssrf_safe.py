"""
Safe HTTP fetching: only requests pre-approved URLs.
This file is intentionally secure — used as a negative fixture for mcpaudit.
"""
import requests

def fetch_report(report_id: str) -> str:
    """Validate input first, then use a fixed URL — user data never enters requests.get()."""
    allowed = {"summary", "status"}
    if report_id not in allowed:
        raise ValueError(f"Unknown report: {report_id!r}")
    # URL is a literal string, completely independent of user input
    return requests.get("https://api.trusted.com/reports/summary").text


def fetch_static() -> str:
    """Fetch a fully literal URL — no user input involved."""
    return requests.get("https://api.trusted.com/status").text
