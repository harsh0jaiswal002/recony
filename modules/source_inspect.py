"""
source_inspect.py
------------------
Reads the already-fetched HTML/JS source (view-source style — no
interaction with the app) and flags things that are useful for a
legitimate recon report: leftover secrets, revealing comments, tech
stack fingerprints, referenced internal endpoints, and forms that
submit sensitive fields insecurely.
"""

import re
import urllib.parse as up

from bs4 import BeautifulSoup, Comment

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key/Secret": r"(?i)(api[_-]?key|secret|token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
}

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Drupal": [r"sites/default/files", r"Drupal\.settings"],
    "jQuery": [r"jquery[-.](\d+\.\d+\.\d+)"],
    "React": [r"react(-dom)?[./]"],
    "Bootstrap": [r"bootstrap(\.min)?\.(css|js)"],
}

SUSPICIOUS_COMMENT_KEYWORDS = [
    "password", "passwd", "secret", "todo", "fixme", "api_key", "apikey", "debug", "internal",
]


def parse_html(html):
    return BeautifulSoup(html, "html.parser")


def extract_comments(soup):
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    flagged = []
    for c in comments:
        text = c.strip()
        if text and any(k in text.lower() for k in SUSPICIOUS_COMMENT_KEYWORDS):
            flagged.append(text[:300])
    return {"total_comments": len(comments), "flagged": flagged}


def extract_inline_scripts(soup):
    scripts = soup.find_all("script")
    return "\n".join(s.string for s in scripts if s.string)


def scan_for_secrets(text):
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            findings.append({"type": name, "count": len(matches)})
    return findings


def detect_tech_stack(html, headers):
    detected = set()
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                detected.add(tech)
                break

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    if server:
        detected.add(f"Server header: {server}")
    if powered_by:
        detected.add(f"X-Powered-By: {powered_by}")

    return sorted(detected)


def extract_endpoints(text):
    """Crude extraction of path-like strings referenced in JS/HTML (recon of
    attack surface — just listing what's referenced, not probing it)."""
    pattern = r"[\"'](/[a-zA-Z0-9_\-/]+\.(?:json|php|asp|aspx|jsp)|/api/[a-zA-Z0-9_\-/]+)[\"']"
    return sorted(set(re.findall(pattern, text)))


def detect_forms(soup, base_url):
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        input_types = [i.get("type", "text") for i in form.find_all("input")]
        has_password = "password" in input_types
        action_url = up.urljoin(base_url, action) if action else base_url
        insecure = has_password and action_url.startswith("http://")
        forms.append({
            "action": action_url,
            "method": method,
            "has_password_field": has_password,
            "insecure_password_submission": insecure,
        })
    return forms
