#!/usr/bin/env python3
"""
recon.py
--------
Passive web recon tool for AUTHORIZED security assessments only.

Usage:
    python recon.py --url https://target.example.com --output report.pdf

What it does:
  - Fetches the page once like a normal browser request (headers, cookies, HTML)
  - Checks TLS config and certificate
  - Checks DNS (SPF/DMARC) and robots.txt
  - Optionally loads the page in headless Chromium to observe network calls,
    storage keys, stylesheets, and console output (requires `playwright install chromium`)
  - Scans the fetched source for leftover secrets, revealing comments, tech
    stack fingerprints, and insecure forms
  - Compiles everything into severity-rated findings with a general "attack
    class" explanation and remediation advice
  - Writes a PDF report

What it deliberately does NOT do:
  - No payload injection, fuzzing, brute-forcing, or exploit attempts
  - No automatic CVE-to-exploit lookup or exploit code generation
  - Any findings here must be manually verified before you report them
"""

import argparse
import sys
from urllib.parse import urlparse

from modules import dynamic_recon
from modules import findings as findings_mod
from modules import report, source_inspect, static_recon


def main():
    parser = argparse.ArgumentParser(
        description="Passive web recon tool for authorized security assessments."
    )
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("--output", default="recon_report.pdf", help="Output PDF path")
    parser.add_argument("--tester", default="", help="Your name/handle, included in the report")
    parser.add_argument("--no-dynamic", action="store_true",
                         help="Skip headless-browser (Playwright) analysis")
    parser.add_argument("--yes-i-am-authorized", action="store_true",
                         help="Skip the interactive authorization confirmation")
    args = parser.parse_args()

    if not args.yes_i_am_authorized:
        confirm = input(
            f"\nYou are about to run reconnaissance traffic against:\n  {args.url}\n"
            "Do you have WRITTEN authorization (a signed scope document, or an active bug bounty "
            "program) to test this target? [yes/NO]: "
        ).strip().lower()
        if confirm != "yes":
            print("Aborting. Only run this against targets you are explicitly authorized to test.")
            sys.exit(1)

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print("Error: --url must be a full URL including scheme, e.g. https://example.com")
        sys.exit(1)

    print(f"[*] Running static recon on {args.url} ...")
    static_results = static_recon.run(args.url)
    if static_results.get("error"):
        print(f"    (warning: {static_results['error']})")

    source_results = {}
    html = static_results.get("html") or ""
    if html:
        print("[*] Inspecting source code ...")
        soup = source_inspect.parse_html(html)
        inline_js = source_inspect.extract_inline_scripts(soup)
        combined = html + "\n" + inline_js
        source_results["comments"] = source_inspect.extract_comments(soup)
        source_results["secrets"] = source_inspect.scan_for_secrets(combined)
        source_results["tech_stack"] = source_inspect.detect_tech_stack(html, static_results.get("headers", {}))
        source_results["endpoints"] = source_inspect.extract_endpoints(combined)
        source_results["forms"] = source_inspect.detect_forms(soup, args.url)

    dynamic_results = {}
    if not args.no_dynamic:
        print("[*] Running dynamic (headless-browser) recon — this can take a bit ...")
        dynamic_results = dynamic_recon.run(args.url)
        target_host = parsed.netloc
        domains = set()
        for req in dynamic_results.get("requests", []):
            host = urlparse(req["url"]).netloc
            if host and host != target_host:
                domains.add(host)
        dynamic_results["third_party_domains"] = sorted(domains)
        for err in dynamic_results.get("errors", []):
            print(f"    (warning: {err})")
    else:
        print("[*] Skipping dynamic recon (--no-dynamic set)")

    print("[*] Compiling findings ...")
    all_findings = findings_mod.compile_findings(static_results, dynamic_results, source_results, args.url)

    print(f"[*] Generating report -> {args.output}")
    report.generate_pdf(all_findings, {"url": args.url, "tester": args.tester}, args.output)

    print(f"\nDone. {len(all_findings)} finding(s) written to {args.output}")
    print("Reminder: verify each finding manually before reporting it, and disclose responsibly "
          "through the organization's official security contact / bug bounty program.")


if __name__ == "__main__":
    main()
