"""Exercise the real local browser/backend. Never prints or records credentials.

Start tests.browser_server and Vite first. ROOTSENTINEL_BROWSER_STATE points to
the external harness directory; ROOTSENTINEL_ORIGIN identifies the Vite origin.
Requires optional backend/requirements-browser.lock and an installed Chrome.
"""
import json
import os
from pathlib import Path

from playwright.sync_api import sync_playwright, expect


def main():
    credentials = json.loads((Path(os.environ["ROOTSENTINEL_BROWSER_STATE"]) / "browser-session.json").read_text())
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        errors = []
        page.on("pageerror", lambda _: errors.append("pageerror"))
        page.goto(os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5173"))
        page.get_by_label("Username", exact=True).fill(credentials["username"])
        page.get_by_label("Password", exact=True).fill(credentials["password"])
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("heading", name="Protected asset registry")).to_be_visible()
        page.get_by_role("button", name="Register synthetic asset").click()
        expect(page.get_by_role("status")).to_contain_text("Synthetic asset registered")
        cases = []
        for fixture, outcome, reason in [("protected", "BLOCK", "EXACT_PROTECTED_FILE"), ("partial", "BLOCK", "BLOCK_THRESHOLD_MET"), ("shifted", "ALLOW", "NO_QUALIFYING_MATCH"), ("benign", "ALLOW", "NO_QUALIFYING_MATCH")]:
            page.get_by_label("Synthetic input").select_option(fixture)
            with page.expect_response(lambda r: "/api/v1/scans?" in r.url and r.request.method == "POST") as response:
                page.get_by_role("button", name="Run scan").click()
            body = response.value.json()
            assert response.value.status == 201
            assert body["decision"]["outcome"] == outcome
            assert body["decision"]["reason"] == reason
            assert body["release_authorized"] is False
            expect(page.get_by_role("heading", name="Policy decision: " + outcome)).to_be_visible()
            cases.append({"fixture": fixture, "outcome": outcome, "reason": reason, "status": "PASS"})
        desktop = page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.set_viewport_size({"width": 390, "height": 844})
        mobile = page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
        assert desktop and mobile and not errors
        result = {"browser": browser.version, "login_registration_logout": "PASS", "cases": cases,
                  "desktop_no_overflow": desktop, "mobile_no_overflow": mobile, "page_errors": len(errors)}
        output = Path(__file__).resolve().parents[1] / "docs/evidence/phase-02-browser.json"
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        browser.close()


if __name__ == "__main__":
    main()
