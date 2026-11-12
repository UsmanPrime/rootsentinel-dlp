"""Anonymous visitor journey in a real browser: no password, synthetic data only, real decisions.

Run against tests.browser_server started with ROOTSENTINEL_BROWSER_VISITOR=1 (visitor mode on, the synthetic seed
assets registered, rule set rs-policy-v2 active), in a NEW external state directory. Nothing here is mocked except
one clearly marked step that renders the cap page from a stubbed 429.
"""
import json
import os
from pathlib import Path

from playwright.sync_api import sync_playwright, expect

from browser_phase04_faults import inject

CSP_HOOK = ("document.addEventListener('securitypolicyviolation', e => console.error('CSP violation: ' + e.violatedDirective + ' '"
            " + (e.blockedURI || 'inline')));")
NETWORK_STATUS = "Failed to load resource"   # Chrome's line for an HTTP error status; the expiry check causes one on purpose.
BENIGN = b"# unrelated synthetic public note\n" * 80


def main():
    state = Path(os.environ["ROOTSENTINEL_BROWSER_STATE"])
    origin = os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5174")
    checks = []

    def passed(name):
        checks.append(name)
        print("PASS " + name, flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=os.environ.get("ROOTSENTINEL_BROWSER_CHANNEL", "chrome") or None, headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True, reduced_motion="reduce")
        context.add_init_script(CSP_HOOK)
        page = context.new_page()
        problems = []
        page.on("console", lambda m: problems.append(m.text[:300]) if m.type == "error" and not m.text.startswith(NETWORK_STATUS) else None)

        def ready():
            page.wait_for_load_state("networkidle")

        def transfer(kind, expected):
            page.goto(origin + "/transfers"); ready()
            page.get_by_role("combobox", name="Synthetic input", exact=True).select_option(kind)
            with page.expect_response(lambda r: "/api/v1/transfers?" in r.url and r.request.method == "POST") as response:
                page.get_by_role("button", name="Evaluate transfer", exact=True).click()
            value = response.value.json()
            assert response.value.status == 201 and value["state"] == expected, value
            expect(page.locator(".verdict-banner")).to_be_visible(); ready()
            return value

        # 1. The entry is on the sign-in page; no credentials are typed anywhere in this journey.
        page.goto(origin + "/login"); ready()
        enter = page.get_by_role("button", name="Explore as visitor", exact=True)
        expect(enter).to_be_visible()
        with page.expect_response(lambda r: r.url.endswith("/api/v1/auth/visitor") and r.request.method == "POST") as entry:
            enter.click()
        assert entry.value.status == 200 and entry.value.json()["user"]["role"] == "VISITOR"
        cookie = next(c for c in context.cookies() if c["name"] == "rs_session")
        assert cookie["httpOnly"] and cookie["sameSite"] == "Strict" and cookie["path"] == "/api/v1"
        expect(page.get_by_role("heading", name="Security overview", exact=True)).to_be_visible(); ready()
        passed("visitor entry without a password and the session cookie flags")

        # 2. The persistent banner and the hidden administrator surface.
        banner = page.locator(".visitor-banner")
        expect(banner).to_contain_text("Visitor mode"); expect(banner).to_contain_text("Synthetic data only")
        expect(banner).to_contain_text("Session ends"); expect(banner).to_contain_text("3 of 3 submissions left")
        navigation = page.get_by_role("navigation", name="Main navigation")
        for hidden in ("Protected Assets", "Integrity Explorer", "Incidents", "Activity & Audit"):
            expect(navigation.get_by_text(hidden, exact=True)).to_have_count(0)
        expect(navigation.get_by_text("My audit trail", exact=True)).to_be_visible()
        page.goto(origin + "/assets"); ready()
        expect(page.get_by_role("heading", name="Access restricted")).to_be_visible()
        denied = context.request.get(origin + "/api/v1/assets")
        assert denied.status == 403 and denied.json()["error"]["code"] == "FORBIDDEN"
        passed("banner, hidden admin navigation and the server's 403 behind it")

        # 3. The real flow: a shifted copy of the synthetic source is blocked by rs-policy-v2, a benign file is allowed.
        blocked = transfer("source_shifted", "BLOCKED")
        assert blocked["scan"]["decision"]["reason"] == "CDC_THRESHOLD_MET", blocked["scan"]["decision"]
        expect(page.get_by_role("button", name="Verified download", exact=True)).to_have_count(0)
        passed("shifted protected source is blocked by the content-defined profile")
        allowed = transfer("benign", "ALLOWED")
        expect(page.get_by_role("button", name="Verified download", exact=True)).to_be_visible()
        page.get_by_role("button", name="Verified download", exact=True).click()
        with page.expect_download() as download:
            page.get_by_role("button", name="Download once", exact=True).click()
        assert Path(download.value.path()).read_bytes() == BENIGN
        ready()
        page.goto(origin + f"/transfers/{allowed['id']}"); ready()
        expect(page.get_by_role("button", name="Verified download", exact=True)).to_have_count(0)
        again = context.request.post(origin + f"/api/v1/transfers/{allowed['id']}/release",
                                     headers={"Origin": origin, "X-CSRF-Token": context.request.get(origin + "/api/v1/auth/me").json()["csrf_token"]})
        assert again.status in {409, 429} and BENIGN not in again.body()
        passed("benign file allowed, released once, never twice")

        # 4. The visitor's own audit trail and the signed head.
        page.goto(origin + "/sandbox-audit"); ready()
        expect(page.get_by_role("heading", name="My audit trail", exact=True)).to_be_visible()
        expect(page.get_by_role("region", name="Visitor audit events")).to_contain_text("VISITOR ENTERED")
        expect(page.get_by_text("VERIFIED", exact=True)).to_be_visible()
        page.get_by_role("button", name="Verify inclusion").first.click()
        expect(page.get_by_text("Included in the signed head", exact=False).first).to_be_visible()
        passed("own audit events, signed tree head and an inclusion proof checked in the browser")

        # 5. Sign out returns to the entry; the banner is gone.
        page.get_by_role("button", name="Sign out").click()
        expect(page.get_by_role("button", name="Explore as visitor", exact=True)).to_be_visible()
        passed("sign out")

        # 6. A fresh sandbox, then an expired one: the friendly page, and a way back in.
        page.get_by_role("button", name="Explore as visitor", exact=True).click()
        expect(banner).to_be_visible(); ready()
        page.goto(origin + "/transfers"); ready()
        inject(state, "expire-session")
        page.get_by_role("button", name="Refresh transfer history").click()
        expect(page.get_by_role("heading", name="Your visitor session has ended")).to_be_visible()
        expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()   # password sign-in stays available
        page.get_by_role("button", name="Start a new visitor session").click()
        expect(banner).to_be_visible(); ready()
        passed("expired visitor session shows the friendly page and a new session starts")

        # 7. The cap page, rendered from a stubbed 429 (the server side of every cap is covered by the backend tests).
        page.get_by_role("button", name="Sign out").click()
        page.route("**/api/v1/auth/visitor", lambda route: route.fulfill(
            status=429, content_type="application/json",
            body=json.dumps({"error": {"code": "VISITOR_DAILY_CAP", "outcome": "INDETERMINATE", "release_authorized": False}})))
        page.get_by_role("button", name="Explore as visitor", exact=True).click()
        expect(page.get_by_role("heading", name="Visitor access is unavailable right now")).to_be_visible()
        expect(page.get_by_text("still works", exact=False)).to_be_visible()
        expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
        passed("cap hit shows the friendly page and password sign-in stays available")

        assert not problems, problems
        assert not page.evaluate("Object.keys(localStorage).length")
        passed("zero CSP violations and no console errors")
        report = {"verdict": "PASS", "checks": checks, "csp_violations": 0,
                  "transport": "Real loopback API with visitor mode on; the cap page uses one stubbed 429"}
        out = Path(os.environ.get("ROOTSENTINEL_BROWSER_EVIDENCE") or state / "evidence"); out.mkdir(parents=True, exist_ok=True)
        (out / "visitor-browser-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2)); browser.close()


if __name__ == "__main__":
    main()
