"""
dynamic_recon.py
-----------------
Loads the page in a real (headless) browser and *observes* what it does —
same as opening DevTools yourself: which requests fire, which cookies get
set, what's in local/session storage (key names only, never values), which
stylesheets load, and any console errors.

This is passive observation of normal page load behavior. It does not
submit forms, click anything, or send any input the page wasn't already
going to generate on its own.
"""

from playwright.sync_api import sync_playwright


def run(url, timeout_ms=30000):
    results = {
        "requests": [],
        "console": [],
        "cookies": [],
        "local_storage_keys": [],
        "session_storage_keys": [],
        "stylesheets": [],
        "errors": [],
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            page.on("request", lambda req: results["requests"].append({
                "url": req.url,
                "method": req.method,
                "resource_type": req.resource_type,
            }))
            page.on("console", lambda msg: results["console"].append({
                "type": msg.type,
                "text": msg.text,
            }))

            page.goto(url, timeout=timeout_ms, wait_until="networkidle")

            results["cookies"] = context.cookies()

            try:
                results["local_storage_keys"] = page.evaluate("Object.keys(window.localStorage)")
                results["session_storage_keys"] = page.evaluate("Object.keys(window.sessionStorage)")
            except Exception as e:
                results["errors"].append(f"storage read failed: {e}")

            try:
                results["stylesheets"] = page.eval_on_selector_all(
                    "link[rel='stylesheet']", "els => els.map(e => e.href)"
                )
            except Exception as e:
                results["errors"].append(f"stylesheet read failed: {e}")

            browser.close()
    except Exception as e:
        results["errors"].append(f"dynamic recon failed (is `playwright install chromium` done?): {e}")

    return results
