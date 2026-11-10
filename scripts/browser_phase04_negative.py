"""Additional actual-browser failure paths on the disposable harness only."""
import json
import os
from pathlib import Path
from uuid import uuid4
from playwright.sync_api import sync_playwright, expect
from browser_phase04_faults import inject


def main():
    state = Path(os.environ["ROOTSENTINEL_BROWSER_STATE"])
    credentials = json.loads((state / "browser-session.json").read_text())
    origin = os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5174")
    checks = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=os.environ.get("ROOTSENTINEL_BROWSER_CHANNEL", "chrome") or None, headless=True)
        context = browser.new_context(viewport={"width": 375, "height": 900})
        context.add_init_script("document.addEventListener('securitypolicyviolation', e => console.error('CSP violation: ' + e.violatedDirective))")
        page = context.new_page()
        csp_violations = []
        page.on("console", lambda m: csp_violations.append(m.text[:200]) if m.type == "error" and ("CSP violation" in m.text or "Content Security Policy" in m.text) else None)
        def login():
            page.goto(origin + "/login"); page.get_by_label("Username", exact=True).fill("browser-admin"); page.get_by_label("Password", exact=True).fill(credentials["password"]); page.get_by_role("button", name="Sign in", exact=True).click(); expect(page.get_by_role("heading", name="Security overview", exact=True)).to_be_visible(); page.wait_for_load_state("networkidle")
        def csrf(): return context.request.get(origin + "/api/v1/auth/me").json()["csrf_token"]
        def submit():
            response = context.request.post(origin + "/api/v1/transfers?filename=negative-synthetic.txt", data=b"unprotected-negative-test-content", headers={"Origin": origin, "X-CSRF-Token": csrf(), "Content-Type": "application/octet-stream", "Idempotency-Key": str(uuid4())})
            assert response.status == 201 and response.json()["state"] == "ALLOWED"
            return response.json()
        login(); transfer = submit(); inject(state, "expire", transfer["id"])
        denied = context.request.post(origin + f"/api/v1/transfers/{transfer['id']}/release", headers={"Origin": origin, "X-CSRF-Token": csrf()})
        assert denied.status == 410 and b"unprotected-negative-test-content" not in denied.body()
        page.goto(origin + f"/transfers/{transfer['id']}"); expect(page.get_by_text("EXPIRED", exact=True)).to_be_visible(); expect(page.get_by_role("button", name="Verified download", exact=True)).to_have_count(0); checks.append("expired transfer UI and real release denial")
        denied = context.request.post(origin + "/api/v1/audit/verify", headers={"Origin": origin}); assert denied.status == 403; checks.append("CSRF rejection")
        # Real offline requests, not mocked error responses. Restore before navigation.
        page.goto(origin + "/transfers"); page.wait_for_load_state("networkidle"); context.set_offline(True); page.get_by_role("button", name="Refresh transfer history").click(); expect(page.get_by_role("alert")).to_be_visible(); assert "Traceback" not in page.locator("main").inner_text(); context.set_offline(False); page.get_by_role("button", name="Try again").click(); expect(page.get_by_role("alert")).to_have_count(0); checks.append("offline error and real recovery")
        # Pending response is held only to test the UI race; the backend response is real.
        submissions = []
        page.on("request", lambda request: submissions.append(request.url) if "/api/v1/transfers?" in request.url and request.method == "POST" else None)
        button = page.get_by_role("button", name="Evaluate transfer", exact=True)
        button.evaluate("element => { element.click(); element.click(); }")
        expect(page.locator(".verdict-banner")).to_be_visible(); assert len(submissions) == 1; checks.append("real same-tick duplicate submission prevention")
        inject(state, "expire-session"); page.get_by_role("button", name="Refresh state").click(); expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible(); expect(page.get_by_text("Your session ended.", exact=False)).to_be_visible(); checks.append("real session expiry clears private workspace")
        login(); approved = submit(); inject(state, "audit-mac")
        page.goto(origin + "/audit"); page.get_by_role("button", name="Verify audit integrity", exact=True).click(); expect(page.get_by_text("FAILED", exact=True)).to_be_visible(); checks.append("tampered audit chain displays actual verification failure")
        page.goto(origin + f"/transfers/{approved['id']}"); page.get_by_role("button", name="Verified download", exact=True).click(); page.get_by_role("button", name="Download once", exact=True).click(); expect(page.get_by_role("alert")).to_be_visible(); assert "unprotected-negative-test-content" not in page.locator("main").inner_text(); checks.append("mandatory audit failure prevents release and safe UI error")
        assert not page.evaluate("Object.keys(localStorage).length")
        assert not csp_violations, csp_violations; checks.append("zero CSP violations on the failure paths")
        report = {"verdict": "PASS", "checks": checks, "csp_violations": 0, "transport": "Real loopback API; controlled faults only in ephemeral synthetic browser database"}
        out = Path(os.environ.get("ROOTSENTINEL_BROWSER_EVIDENCE") or state / "evidence"); out.mkdir(parents=True, exist_ok=True)
        (out / "negative-browser-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2)); browser.close()


if __name__ == "__main__": main()
