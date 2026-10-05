# Ethical Recon Tool

A passive web reconnaissance tool for **authorized** security assessments.
Give it a URL; it observes headers, TLS, DNS, cookies, source code, and
(optionally) live network/storage behavior via a headless browser, then
writes a PDF report of findings — each tagged with severity, the general
*class* of attack it relates to, and remediation advice.

## Before you use this on anything

This only belongs pointed at:
- A site you own, **or**
- A site with a signed scope/authorization document (a pentest engagement letter), **or**
- A live bug bounty program (HackerOne, Bugcrowd, Intigriti, etc.) where the
  target is explicitly in scope.

Scanning a site you don't have permission to test is illegal in most
jurisdictions (e.g. the US Computer Fraud and Abuse Act), regardless of
intent. The tool will ask you to confirm authorization before it runs.

## What it does

- **Static recon** (`modules/static_recon.py`): one normal HTTP GET, TLS
  handshake inspection, DNS (SPF/DMARC), `robots.txt`, cookie flags
  (Secure/HttpOnly/SameSite), security headers.
- **Dynamic recon** (`modules/dynamic_recon.py`): loads the page in headless
  Chromium (Playwright) and records network requests, console messages,
  cookies actually set, `localStorage`/`sessionStorage` **key names only**
  (never values — avoids capturing live session tokens in your report),
  and loaded stylesheets.
- **Source inspection** (`modules/source_inspect.py`): scans fetched
  HTML/JS for leftover secrets (API keys, JWTs), suspicious developer
  comments, tech-stack fingerprints, referenced internal endpoints, and
  forms that submit passwords over plain HTTP.
- **Findings + report** (`modules/findings.py`, `modules/report.py`):
  normalizes everything into severity-rated findings and renders a PDF.

## What it deliberately does NOT do

- No payload injection, fuzzing, brute-forcing, or login attempts.
- No automatic "find a public exploit for this version and run it."
- It doesn't decide anything is *definitely* exploitable — it flags
  conditions that are commonly associated with a class of attack. You
  still have to verify each finding manually before reporting it.

If you want to go from "finding" to "confirmed vulnerability," that's the
actual skill of pentesting — manually testing each lead, in scope, with a
tool like Burp Suite, and cross-referencing disclosed software versions
against the NVD/CVE database yourself.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium     # only needed for dynamic recon
```

## Usage

```bash
python recon.py --url https://target.example.com --output report.pdf --tester "your-handle"
```

Flags:
- `--no-dynamic` — skip the headless-browser pass (faster, no Playwright/Chromium needed)
- `--yes-i-am-authorized` — skip the interactive confirmation prompt (for scripting; use responsibly)
- `--output` — PDF path (default `recon_report.pdf`)

## Extending it

Good next steps if you want to keep learning:
- Add more checks to `findings.py` (CORS misconfig, cache-control on
  sensitive pages, subdomain takeover candidates from DNS CNAMEs, etc.)
- Add batch mode: loop `recon.run()` over a list of in-scope URLs from a file.
- For version-based findings (e.g. an outdated jQuery or disclosed server
  version), look up the CVEs yourself on nvd.nist.gov before including them
  in a client-facing report — don't take a scanner's word for exploitability.
# recony
# recony
