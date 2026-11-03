"""Real Chrome/HTTP acceptance. Credentials and downloads remain external."""
from hashlib import sha256
import json
import os
from pathlib import Path
from uuid import uuid4
from playwright.sync_api import sync_playwright, expect


def main():
    state = Path(os.environ["ROOTSENTINEL_BROWSER_STATE"])
    credentials = json.loads((state / "browser-session.json").read_text())
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1100}, accept_downloads=True)
        page = context.new_page(); errors = []
        page.on("pageerror", lambda _: errors.append("pageerror"))
        page.goto(os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5173"))
        page.get_by_label("Username", exact=True).fill(credentials["username"])
        page.get_by_label("Password", exact=True).fill(credentials["password"])
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("heading", name="Controlled transfer gateway")).to_be_visible()
        page.get_by_label("Asset label").fill("Browser synthetic " + uuid4().hex[:8])
        page.get_by_role("button", name="Register synthetic asset").click()
        expect(page.get_by_text("Synthetic asset registered.", exact=False)).to_be_visible()
        cases = []
        for fixture, expected in [("protected", "BLOCKED"), ("partial", "BLOCKED"), ("benign", "ALLOWED")]:
            page.get_by_label("Transfer fixture", exact=True).select_option(fixture)
            with page.expect_response(lambda r: "/api/v1/transfers?" in r.url and r.request.method == "POST") as observed:
                page.get_by_role("button", name="Submit transfer", exact=True).click()
            response = observed.value; item = response.json()
            assert response.status == 201 and item["state"] == expected
            expect(page.get_by_role("heading", name="Transfer state: " + expected, exact=True)).to_be_visible()
            if expected == "BLOCKED":
                expect(page.get_by_role("button", name="Verified download", exact=True)).to_be_disabled()
                # Forge direct request independently of the disabled UI.
                direct = page.evaluate('''async id => {
                    const me = await (await fetch('/api/v1/auth/me')).json();
                    const r = await fetch('/api/v1/transfers/' + id + '/release', {method:'POST', headers:{'X-CSRF-Token':me.csrf_token}});
                    return {status:r.status, body:await r.text()};
                }''', item["id"])
                assert direct["status"] == 409 and "synthetic RootSentinel fixture" not in direct["body"]
                expect(page.get_by_role("heading", name="Incident: OPEN", exact=True)).to_be_visible()
                page.get_by_label("Investigation note").fill("Synthetic classroom verification")
                page.get_by_role("button", name="Mark investigating", exact=True).click()
                expect(page.get_by_role("heading", name="Incident: INVESTIGATING", exact=True)).to_be_visible()
                page.get_by_label("Resolution reason").fill("Authorized local training")
                page.get_by_role("button", name="Resolve incident", exact=True).click()
                expect(page.get_by_role("heading", name="Incident: RESOLVED", exact=True)).to_be_visible()
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="Export incident JSON", exact=True).click()
                evidence = json.loads(Path(downloaded.value.path()).read_bytes())
                assert evidence["incident"]["scan"]["decision"]["outcome"] == "BLOCK"
                downloaded.value.delete()
                cases.append({"fixture": fixture, "state": expected, "forged_release_status": 409, "incident_resolution_and_export": "PASS"})
            else:
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="Verified download", exact=True).click()
                data = Path(downloaded.value.path()).read_bytes()
                expected_bytes = b"# unrelated synthetic public note\n" * 80
                assert data == expected_bytes
                digest = sha256(data).hexdigest()
                assert digest == item["file_sha256"]
                downloaded.value.delete()
                expect(page.get_by_role("heading", name="Transfer state: STREAM_FINISHED", exact=True)).to_be_visible()
                cases.append({"fixture": fixture, "state": expected, "download_bytes": len(data), "independent_sha256": digest, "byte_equality": "PASS"})
        page.get_by_role("button", name="Verify audit chain", exact=True).click()
        expect(page.get_by_text("Audit verified through event", exact=False)).to_be_visible()
        desktop = page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.set_viewport_size({"width": 390, "height": 844})
        mobile = page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert desktop and mobile and not errors
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
        report = {"browser": browser.version, "transport": "real loopback HTTP through Vite to Uvicorn",
            "cases": cases, "audit_verification": "PASS", "desktop_no_overflow": desktop,
            "mobile_no_overflow": mobile, "page_errors": len(errors), "login_logout": "PASS"}
        target = Path(__file__).resolve().parents[1] / "docs/evidence/phase-03-browser.json"
        target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2)); browser.close()


if __name__ == "__main__": main()
