"""
static_recon.py
----------------
Passive, non-intrusive data collection: a single normal HTTP GET, a TLS
handshake inspection, public DNS lookups, and a fetch of robots.txt.

Nothing here sends anything other than a standard page request — no
parameter fuzzing, no payloads, no login attempts.
"""

import datetime
import socket
import ssl
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests

DEFAULT_HEADERS = {
    # Identify the tool honestly in logs — good practice for authorized testing.
    "User-Agent": "EthicalReconTool/1.0 (+authorized-security-assessment)"
}


def run(url, timeout=10):
    """Run all static/passive checks against a single URL."""
    results = {}

    try:
        resp = requests.get(
            url, headers=DEFAULT_HEADERS, timeout=timeout,
            verify=True, allow_redirects=True,
        )
        results["status_code"] = resp.status_code
        results["headers"] = dict(resp.headers)
        results["html"] = resp.text
        results["final_url"] = resp.url
        results["cookie_flags"] = _parse_cookies(resp)
    except requests.RequestException as e:
        results["error"] = f"HTTP request failed: {e}"
        results["headers"] = {}
        results["html"] = ""
        results["cookie_flags"] = []

    parsed = urlparse(url)
    hostname = parsed.hostname

    results["tls"] = _get_tls_info(hostname) if (parsed.scheme == "https" and hostname) else {}
    results["dns"] = _get_dns_records(hostname) if hostname else {}
    results["robots"] = _check_robots(url)

    return results


def _parse_cookies(resp):
    """Pull Set-Cookie headers and check Secure/HttpOnly/SameSite flags."""
    cookies = []
    raw_cookies = None
    try:
        if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "get_all"):
            raw_cookies = resp.raw.headers.get_all("Set-Cookie")
    except Exception:
        raw_cookies = None

    if not raw_cookies:
        single = resp.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0] if parts and "=" in parts[0] else "unknown"
        lower = raw.lower()
        cookies.append({
            "name": name,
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": "samesite" in lower,
            "raw": raw,
        })
    return cookies


def _get_tls_info(hostname, port=443):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    info["expires"] = expiry.isoformat()
                    info["days_to_expiry"] = (expiry - datetime.datetime.utcnow()).days
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
    except Exception as e:
        info["error"] = str(e)
    return info


def _get_dns_records(hostname):
    info = {"txt": [], "spf": False, "dmarc": False}

    try:
        info["a"] = [a.to_text() for a in dns.resolver.resolve(hostname, "A")]
    except Exception:
        info["a"] = []

    try:
        info["mx"] = [a.to_text() for a in dns.resolver.resolve(hostname, "MX")]
    except Exception:
        info["mx"] = []

    try:
        for a in dns.resolver.resolve(hostname, "TXT"):
            txt = a.to_text()
            info["txt"].append(txt)
            if "v=spf1" in txt:
                info["spf"] = True
    except Exception:
        pass

    try:
        for a in dns.resolver.resolve(f"_dmarc.{hostname}", "TXT"):
            if "v=DMARC1" in a.to_text():
                info["dmarc"] = True
    except Exception:
        pass

    return info


def _check_robots(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = urljoin(base, "/robots.txt")
    result = {"disallow": [], "sensitive_paths_disclosed": False}

    try:
        resp = requests.get(robots_url, headers=DEFAULT_HEADERS, timeout=8)
        if resp.status_code == 200:
            sensitive_keywords = ["admin", "wp-admin", "internal", "backup", "config", "private", ".git"]
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    result["disallow"].append(path)
                    if any(k in path.lower() for k in sensitive_keywords):
                        result["sensitive_paths_disclosed"] = True
    except requests.RequestException:
        pass

    return result
