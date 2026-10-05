"""
findings.py
-----------
Turns raw recon output into a list of Finding objects. Each finding
names the GENERAL CLASS of attack a weakness could contribute to
(the same way Mozilla Observatory / SecurityHeaders.com / OWASP do it)
— never a specific payload, exploit script, or step-by-step attack.

Severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
"""

from dataclasses import dataclass

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    evidence: str
    attack_category: str
    remediation: str


HEADER_CHECKS = {
    "Content-Security-Policy": (
        "Missing Content-Security-Policy Header", "HIGH",
        "Attack class: Cross-Site Scripting (XSS) impact amplification. Without a CSP, any script that ends up "
        "running on the page — via an existing XSS bug, a compromised third-party script, etc. — executes with "
        "no browser-enforced restriction on what it can load, read, or send.",
        "Define a restrictive Content-Security-Policy, starting from default-src 'self' and adding exceptions as needed.",
    ),
    "Strict-Transport-Security": (
        "Missing HSTS Header", "MEDIUM",
        "Attack class: SSL stripping / man-in-the-middle. On an untrusted network, an attacker can force the "
        "browser down to plain HTTP and intercept traffic before HTTPS is ever established.",
        "Add Strict-Transport-Security with a long max-age, and includeSubDomains/preload once verified safe.",
    ),
    "X-Frame-Options": (
        "Missing X-Frame-Options / frame-ancestors", "MEDIUM",
        "Attack class: Clickjacking. The page can be embedded in a hidden iframe on an attacker's site to trick "
        "users into clicking UI elements they can't actually see.",
        "Set X-Frame-Options: DENY or SAMEORIGIN, or a frame-ancestors directive in your CSP.",
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options", "LOW",
        "Attack class: MIME-sniffing based execution — a file meant to be served as inert data gets interpreted "
        "and executed as script/HTML by the browser instead.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "Referrer-Policy": (
        "Missing Referrer-Policy", "LOW",
        "Attack class: Information leakage. Full URLs — sometimes containing tokens or sensitive query "
        "parameters — can leak to third-party sites via the Referer header.",
        "Set an explicit Referrer-Policy, e.g. strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "Missing Permissions-Policy", "INFO",
        "Attack class: Unrestricted use of powerful browser features (camera, geolocation, microphone, etc.) by "
        "embedded or compromised third-party scripts.",
        "Define a Permissions-Policy that disables browser features the site doesn't use.",
    ),
}


def compile_findings(static_results, dynamic_results, source_results, url):
    findings = []
    headers = static_results.get("headers", {}) or {}
    lower_header_keys = {h.lower() for h in headers}

    for header, (title, sev, attack, remediation) in HEADER_CHECKS.items():
        if header.lower() not in lower_header_keys:
            findings.append(Finding(
                id=f"missing-{header.lower()}", title=title, severity=sev,
                description=f"The response did not include a '{header}' header.",
                evidence=f"Checked response headers for {url}",
                attack_category=attack, remediation=remediation,
            ))

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    if server or powered_by:
        findings.append(Finding(
            id="server-version-disclosure", title="Server/Technology Version Disclosure", severity="LOW",
            description=f"The server discloses technology/version details: "
                        f"{', '.join(filter(None, [server, powered_by]))}",
            evidence=f"Server: {server or 'N/A'}, X-Powered-By: {powered_by or 'N/A'}",
            attack_category="Attack class: Targeted exploitation reconnaissance. Anyone can cross-reference the "
                            "disclosed software/version against public vulnerability databases (e.g. NVD) before "
                            "deciding how to approach the target — this report does not do that lookup for you.",
            remediation="Suppress or genericize Server/X-Powered-By headers at the web server or framework level.",
        ))

    for cookie in static_results.get("cookie_flags", []) or []:
        missing = []
        if not cookie.get("secure"):
            missing.append("Secure")
        if not cookie.get("httponly"):
            missing.append("HttpOnly")
        if not cookie.get("samesite"):
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                id=f"cookie-flags-{cookie.get('name')}",
                title=f"Cookie '{cookie.get('name')}' missing {'/'.join(missing)}",
                severity="MEDIUM" if ("HttpOnly" in missing or "Secure" in missing) else "LOW",
                description=f"Cookie '{cookie.get('name')}' is missing: {', '.join(missing)}.",
                evidence=cookie.get("raw", str(cookie)),
                attack_category="Attack class: Session hijacking. Without HttpOnly, any script running on the "
                                "page (e.g. via an unrelated XSS bug) can read this cookie; without Secure it can "
                                "be sent over and intercepted on an unencrypted connection; without SameSite it is "
                                "more exposed to cross-site request forgery.",
                remediation="Set Secure, HttpOnly, and an appropriate SameSite value on session-related cookies.",
            ))

    tls = static_results.get("tls", {}) or {}
    if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(Finding(
            id="weak-tls-protocol", title=f"Outdated TLS Protocol In Use ({tls.get('protocol')})", severity="HIGH",
            description=f"The server negotiated {tls.get('protocol')}, which is deprecated.",
            evidence=str(tls),
            attack_category="Attack class: Traffic decryption / downgrade attacks (the specific family of issue "
                            "depends on the exact protocol and cipher negotiated).",
            remediation="Disable TLS 1.0/1.1/SSLv3 and enforce TLS 1.2+ only.",
        ))
    days = tls.get("days_to_expiry")
    if days is not None and days < 14:
        findings.append(Finding(
            id="tls-cert-expiring", title="TLS Certificate Expiring Soon", severity="MEDIUM",
            description=f"Certificate expires in {days} day(s).",
            evidence=str(tls),
            attack_category="Attack class: Service disruption / trust erosion. Not directly exploitable, but it "
                            "trains users to click through browser security warnings once it lapses.",
            remediation="Renew and automate certificate renewal (e.g. via ACME/Let's Encrypt).",
        ))

    dns_info = static_results.get("dns", {}) or {}
    if not dns_info.get("spf"):
        findings.append(Finding(
            id="missing-spf", title="Missing SPF Record", severity="LOW",
            description="No SPF TXT record was found for the domain.",
            evidence=str(dns_info.get("txt", [])),
            attack_category="Attack class: Email spoofing. Without SPF it's easier for an attacker to send "
                            "phishing email that appears to come from this domain.",
            remediation="Publish an SPF record scoped to your legitimate mail senders.",
        ))
    if not dns_info.get("dmarc"):
        findings.append(Finding(
            id="missing-dmarc", title="Missing DMARC Record", severity="LOW",
            description="No DMARC TXT record was found for the domain.",
            evidence="",
            attack_category="Attack class: Email spoofing / phishing using the organization's domain name.",
            remediation="Publish a DMARC record (start with p=none while monitoring, then move to quarantine/reject).",
        ))

    robots = static_results.get("robots", {}) or {}
    if robots.get("sensitive_paths_disclosed"):
        findings.append(Finding(
            id="robots-sensitive-paths", title="robots.txt Discloses Sensitive-Looking Paths", severity="INFO",
            description="robots.txt lists paths that hint at admin/internal areas.",
            evidence=str(robots.get("disallow", [])),
            attack_category="Attack class: Attack-surface mapping. robots.txt is public — listing sensitive-"
                            "looking paths there just tells an attacker where to look first.",
            remediation="Don't rely on robots.txt to hide sensitive paths; rely on proper authentication instead.",
        ))

    for s in source_results.get("secrets", []) or []:
        findings.append(Finding(
            id=f"exposed-secret-{s['type'].lower().replace(' ', '-').replace('/', '-')}",
            title=f"Possible Exposed Secret in Client-Side Code: {s['type']}", severity="CRITICAL",
            description=f"Found {s['count']} pattern match(es) resembling a {s['type']} in page/script source.",
            evidence="Pattern matched in client-side JavaScript (value redacted in this report).",
            attack_category="Attack class: Direct credential abuse. If genuine, this key/token could let an "
                            "attacker call backend services or third-party APIs directly, bypassing the app.",
            remediation="Remove the secret from client-side code immediately, rotate it, and move it server-side.",
        ))

    comments = source_results.get("comments", {}) or {}
    if comments.get("flagged"):
        findings.append(Finding(
            id="suspicious-html-comments", title="Suspicious HTML Comments Found", severity="LOW",
            description=f"{len(comments['flagged'])} comment(s) contain keywords like 'password', 'secret', "
                        f"'debug', etc.",
            evidence="; ".join(comments["flagged"][:3]),
            attack_category="Attack class: Information disclosure. Developer comments sometimes leak internal "
                            "logic, leftover credentials, or hints about unfinished/debug functionality.",
            remediation="Strip developer comments from production HTML/JS before deployment.",
        ))

    for form in source_results.get("forms", []) or []:
        if form.get("insecure_password_submission"):
            findings.append(Finding(
                id="insecure-password-form", title="Password Submitted Over Insecure Connection", severity="CRITICAL",
                description=f"A form with a password field submits to {form['action']} over plain HTTP.",
                evidence=str(form),
                attack_category="Attack class: Credential interception. Anyone on the network path between user "
                                "and server can read the submitted password in plaintext.",
                remediation="Serve the entire site over HTTPS and ensure all forms submit to HTTPS endpoints.",
            ))

    third_party = (dynamic_results or {}).get("third_party_domains", [])
    if third_party:
        findings.append(Finding(
            id="third-party-resources", title=f"{len(third_party)} Third-Party Domain(s) Loaded", severity="INFO",
            description="The page loads resources from external domains.",
            evidence=", ".join(third_party[:15]),
            attack_category="Attack class: Supply-chain risk. If any third-party script is compromised, it runs "
                            "with the same privileges as the site's own code unless constrained by CSP/SRI.",
            remediation="Use Subresource Integrity (SRI) for third-party scripts and a CSP to limit allowed sources.",
        ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 5))
    return findings
