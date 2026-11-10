"""Real Chrome + loopback API journeys; synthetic data only, no mocked verdicts.

Run against tests.browser_server in a NEW external state directory. Credentials,
downloads and browser profiles stay external. Only sanitized evidence is saved.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import time
from uuid import uuid4

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
AXE = (ROOT / "frontend/node_modules/axe-core/axe.min.js").read_text(encoding="utf-8")
# Every CSP violation is also written to the console, so one listener catches them across navigations.
CSP_HOOK = ("document.addEventListener('securitypolicyviolation', e => console.error('CSP violation: ' + e.violatedDirective + ' '"
            " + (e.blockedURI || 'inline')));")
NETWORK_STATUS = "Failed to load resource"   # Chrome's line for an HTTP error status; the negative checks cause these on purpose.


def main():
    state = Path(os.environ["ROOTSENTINEL_BROWSER_STATE"])
    credentials = json.loads((state / "browser-session.json").read_text())
    origin = os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5174")
    # Output stays outside the repository by default, so a run never rewrites the recorded Phase 04 evidence.
    OUT = Path(os.environ.get("ROOTSENTINEL_BROWSER_EVIDENCE") or state / "evidence")
    OUT.mkdir(parents=True, exist_ok=True)
    report = {"transport": "Chrome / real loopback HTTP / SQLite", "checks": [], "accessibility": [], "responsive": [], "screenshots": [], "timings_ms": {}}
    def passed(name):
        report["checks"].append(name)
        print("PASS " + name, flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=os.environ.get("ROOTSENTINEL_BROWSER_CHANNEL", "chrome") or None, headless=True)
        report["browser"] = browser.version
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True, reduced_motion="reduce")
        context.add_init_script(CSP_HOOK)
        page = context.new_page(); errors = []; broken_assets = []; console_errors = []
        page.on("console", lambda m: console_errors.append(m.text[:300]) if m.type == "error" and not m.text.startswith(NETWORK_STATUS) else None)
        page.on("pageerror", lambda _: errors.append("uncaught JavaScript error"))
        page.on("response", lambda r: broken_assets.append(r.status) if r.status >= 400 and r.request.resource_type in {"script", "stylesheet", "image", "font"} else None)
        def ready():
            page.wait_for_load_state("networkidle")
        def visit(path):
            page.goto(origin + path); ready()
        def screenshot(name):
            ready(); page.screenshot(path=str(OUT / (name + ".png")), full_page=True, animations="disabled")
            report["screenshots"].append(name + ".png")
        def axe(name):
            page.evaluate(AXE)   # evaluated through the browser's debugging protocol, which the page's CSP does not govern
            result = page.evaluate("async () => { const r = await axe.run(document, {runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}}); return {violations:r.violations.map(v=>({id:v.id,impact:v.impact,targets:v.nodes.map(n=>n.target)})), incomplete:r.incomplete.length}; }")
            report["accessibility"].append({"page": name, **result})
            assert not result["violations"], json.dumps(result["violations"])
        def login(username):
            visit("/login"); page.get_by_label("Username", exact=True).fill(username); page.get_by_label("Password", exact=True).fill(credentials["password"])
            page.get_by_role("button", name="Sign in", exact=True).click(); expect(page.get_by_role("heading", name="Security overview", exact=True)).to_be_visible(); ready()
        def csrf():
            return context.request.get(origin + "/api/v1/auth/me").json()["csrf_token"]
        def raw(path, data, token=None):
            return context.request.post(origin + "/api/v1" + path, data=data, headers={"Origin": origin, "X-CSRF-Token": token or csrf(), "Content-Type": "application/octet-stream", "Idempotency-Key": str(uuid4())})
        def register(label, kind="protected"):
            visit("/assets"); page.get_by_role("button", name="Register asset", exact=True).click(); page.get_by_label("Asset label", exact=True).fill(label); page.get_by_label("Registration input").select_option(kind)
            with page.expect_response(lambda r: "/api/v1/assets?" in r.url and r.request.method == "POST") as response:
                page.get_by_role("button", name="Register fingerprints").click()
            value = response.value.json(); assert response.value.status == 201, value
            expect(page.get_by_role("heading", name=label, exact=True)).to_be_visible(); ready(); return value
        def transfer(kind, expected):
            visit("/transfers"); page.get_by_role("combobox", name="Synthetic input", exact=True).select_option(kind)
            started = time.perf_counter()
            with page.expect_response(lambda r: "/api/v1/transfers?" in r.url and r.request.method == "POST") as response:
                page.get_by_role("button", name="Evaluate transfer", exact=True).click()
            value = response.value.json(); assert response.value.status == 201 and value["state"] == expected, value
            expect(page.locator(".verdict-banner")).to_be_visible(); ready(); report["timings_ms"][kind + "_submit_to_visible"] = round((time.perf_counter() - started) * 1000, 2); return value
        try:
            served = page.goto(origin + "/login"); ready()
            policy = served.headers.get("content-security-policy", "")
            assert "default-src 'none'" in policy and "unsafe-inline" not in policy and "content-security-policy-report-only" not in served.headers, policy
            report["content_security_policy"] = "enforced"; passed("interface served with the enforced content security policy")
            axe("login"); screenshot("login-desktop")
            page.get_by_label("Username", exact=True).fill("nonexistent-synthetic-user"); page.get_by_label("Password", exact=True).fill("invalid-synthetic-password")
            page.get_by_role("button", name="Sign in", exact=True).click(); expect(page.get_by_role("alert")).to_be_visible(); passed("invalid login safely rejected")
            login("browser-admin"); passed("administrator login")
            visit("/assets"); expect(page.get_by_role("heading", name="No assets found")).to_be_visible(); passed("empty registry")
            visit("/incidents"); expect(page.get_by_role("heading", name="No incidents in this view")).to_be_visible(); passed("empty incidents")
            protected = register("Synthetic source service"); passed("asset registration and details")
            screenshot("asset-details-desktop"); axe("asset details")
            # Native dialog: focus remains inside, Escape closes and restores trigger.
            trigger = page.get_by_role("button", name="Retire asset", exact=True); trigger.click()
            for _ in range(12):
                page.keyboard.press("Tab"); assert page.evaluate("document.querySelector('dialog[open]').contains(document.activeElement)")
            page.keyboard.press("Escape"); expect(trigger).to_be_focused(); passed("dialog keyboard trap, Escape and focus restoration")
            odd = register("Uneven three-chunk fixture", "odd")
            visit(f"/integrity?asset={odd['asset_id']}&version={odd['id']}")
            expect(page.locator("g.tree-node")).to_have_count(5)
            page.get_by_role("button", name="Verify inclusion", exact=True).click(); expect(page.get_by_text("Original proof: VERIFIED", exact=True)).to_be_visible()
            page.get_by_role("button", name="Test tampered copy", exact=True).click(); expect(page.get_by_text("Tampered copy: REJECTED", exact=True)).to_be_visible()
            chunk = page.get_by_role("button", name="Select chunk 2", exact=True); chunk.focus(); page.keyboard.press("Enter")
            expect(page.get_by_role("heading", name="Chunk 2 · inclusion proof", exact=True)).to_be_visible()
            page.get_by_role("button", name="Verify inclusion", exact=True).click(); expect(page.get_by_text("Original proof: VERIFIED", exact=True)).to_be_visible()
            screenshot("integrity-desktop"); axe("integrity"); passed("uneven tree, keyboard leaf selection, valid and tampered backend proofs")
            page.get_by_role("button", name="Fingerprint empty input").click(); expect(page.get_by_text("No leaves; no inclusion proof exists.", exact=False)).to_be_visible(); passed("empty input backend fingerprint")
            large_data = b"L" * (1024 * 1025)
            large = raw("/assets?label=Large-synthetic-tree", large_data).json()
            visit(f"/integrity?asset={large['asset_id']}&version={large['id']}"); assert page.locator("g.tree-node").count() <= 31
            expect(page.get_by_role("button", name="Select chunk 15", exact=True)).to_be_visible(); passed("1025-leaf tree renders bounded proof path")
            blocked = transfer("renamed", "BLOCKED"); assert blocked["scan"]["decision"]["reason"] == "EXACT_PROTECTED_FILE"
            expect(page.get_by_role("button", name="Verified download", exact=True)).to_have_count(0)
            denied = context.request.post(origin + f"/api/v1/transfers/{blocked['id']}/release", headers={"Origin": origin, "X-CSRF-Token": csrf()})
            assert denied.status == 409 and b"synthetic" not in denied.body().lower()
            screenshot("blocked-transfer-desktop"); axe("blocked transfer"); passed("renamed BLOCK and forged release denial with no payload")
            partial = transfer("partial", "BLOCKED"); assert partial["scan"]["decision"]["reason"] == "BLOCK_THRESHOLD_MET"; passed("real partial-block match")
            allowed = transfer("benign", "ALLOWED")
            started = time.perf_counter()
            page.get_by_role("button", name="Verified download", exact=True).click()
            expect(page.get_by_role("dialog")).to_contain_text("single time")
            with page.expect_download() as download:
                page.get_by_role("button", name="Download once", exact=True).click()
            data = Path(download.value.path()).read_bytes(); assert data == b"# unrelated synthetic public note\n" * 80
            assert sha256(data).hexdigest() == allowed["file_sha256"]
            report["download"] = {"bytes": len(data), "sha256": sha256(data).hexdigest(), "byte_equality": True}
            download.value.delete(); report["timings_ms"]["release_and_browser_hash"] = round((time.perf_counter() - started) * 1000, 2)
            expect(page.get_by_text("Received response bytes matched", exact=False)).to_be_visible(); passed("actual downloaded bytes independently equal scanned bytes")
            screenshot("allowed-release-desktop"); axe("released transfer")
            incident_id = blocked["incident_id"]; visit(f"/incidents/{incident_id}")
            page.get_by_role("button", name="Update investigation").click(); page.get_by_role("combobox", name="Investigation status", exact=True).select_option("INVESTIGATING"); page.get_by_label("Analyst note", exact=True).fill("Synthetic classroom observation; source content withheld.")
            page.get_by_role("button", name="Save investigation").click(); expect(page.get_by_text("Synthetic classroom observation; source content withheld.", exact=True)).to_be_visible(); passed("incident status and persisted analyst note")
            with page.expect_download() as export:
                page.get_by_role("button", name="Export evidence", exact=True).click()
            evidence = json.loads(Path(export.value.path()).read_text()); assert evidence and "password" not in json.dumps(evidence).lower(); export.value.delete(); passed("authorized sanitized evidence export")
            screenshot("incident-desktop"); axe("incident detail")
            visit("/incidents"); page.get_by_role("combobox", name="Status", exact=True).select_option("INVESTIGATING"); expect(page.get_by_role("link", name=incident_id[:8], exact=True)).to_be_visible(); passed("server-side incident status filter")
            visit("/audit"); page.get_by_role("button", name="Verify audit integrity", exact=True).click(); expect(page.get_by_text("VERIFIED", exact=True)).to_be_visible(); passed("HMAC verification through real API")
            screenshot("audit-desktop"); axe("audit")
            page.get_by_role("button", name="Retain checkpoint", exact=True).click(); page.get_by_role("button", name="Confirm checkpoint").click(); expect(page.get_by_text("The backend retained a checkpoint", exact=False)).to_be_visible(); passed("authorized external checkpoint retention")
            # Preserve old asset versions and exercise retirement without affecting primary sample.
            visit(f"/assets/{odd['asset_id']}"); page.get_by_role("button", name="New version", exact=True).click(); page.get_by_label("Registration input").select_option("protected"); page.get_by_role("button", name="Register fingerprints").click(); expect(page.get_by_role("heading", name="Version 2", exact=True)).to_be_visible(); expect(page.get_by_role("heading", name="Version 1", exact=True)).to_be_visible(); passed("immutable version history")
            page.get_by_role("button", name="Retire asset", exact=True).click(); page.get_by_role("button", name="Confirm retirement").click(); expect(page.get_by_text("RETIRED", exact=True)).to_be_visible(); passed("retirement confirmation preserves historical versions")
            stale = transfer("benign", "ALLOWED")
            visit("/policies"); page.get_by_role("button", name="Create policy version").click(); page.get_by_label("Minimum matched outbound bytes").fill("1024"); page.get_by_role("button", name="Confirm new version").click(); expect(page.get_by_text("is now active.", exact=False)).to_be_visible(); passed("new immutable policy version")
            screenshot("policies-desktop"); axe("policies")
            visit(f"/transfers/{stale['id']}"); page.get_by_role("button", name="Verified download", exact=True).click(); page.get_by_role("button", name="Download once", exact=True).click(); expect(page.get_by_role("alert")).to_be_visible(); expect(page.get_by_role("button", name="Verified download", exact=True)).to_have_count(0); passed("stale release fails closed and UI refreshes")
            visit("/transfers/00000000-0000-4000-8000-000000000000"); expect(page.get_by_role("alert")).to_be_visible(); passed("missing transfer safe error")
            # Guide actions exercise live backend, with no fixture response mocking.
            visit("/guide"); page.get_by_role("button", name="02 Register a synthetic asset").click(); page.get_by_role("button", name="Register guide sample").click(); expect(page.get_by_text("Registered version 1.", exact=False)).to_be_visible()
            page.get_by_role("button", name="04 Verify inclusion").click(); page.get_by_role("button", name="Verify original proof").click(); expect(page.get_by_text("VERIFIED", exact=True)).to_be_visible()
            page.get_by_role("button", name="05 Test a tampered proof").click(); page.get_by_role("button", name="Verify tampered copy").click(); expect(page.get_by_text("REJECTED", exact=True)).to_be_visible()
            page.get_by_role("button", name="06 Submit a renamed copy").click(); page.get_by_role("button", name="Evaluate renamed copy").click(); expect(page.get_by_text("BLOCKED", exact=True)).to_be_visible()
            page.get_by_role("button", name="08 Submit a benign sample").click(); page.get_by_role("button", name="Evaluate benign sample").click(); expect(page.get_by_text("ALLOWED", exact=True)).to_be_visible(); passed("guided demonstration uses real registry, proofs and transfer decisions")
            screenshot("guide-desktop"); axe("guide")
            # Exact route data and responsive behavior across all requested widths.
            routes = [("overview", "/"), ("gateway", "/transfers"), ("assets", "/assets"), ("integrity", f"/integrity?asset={protected['asset_id']}&version={protected['id']}"), ("incidents", "/incidents"), ("audit", "/audit"), ("policies", "/policies"), ("guide", "/guide")]
            for width in (320, 375, 768, 1024, 1440, 1920):
                page.set_viewport_size({"width": width, "height": 1000})
                for name, route in routes:
                    visit(route); assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"overflow {name} {width}"
                    report["responsive"].append({"route": name, "width": width, "no_page_overflow": True})
                    if width in (375, 1440): screenshot(f"{name}-{width}")
                    if width == 375: axe(name + " mobile")
                if width == 375:
                    page.get_by_role("button", name="Open navigation").click(); expect(page.get_by_role("dialog")).to_be_visible(); page.keyboard.press("Escape"); expect(page.get_by_role("dialog")).to_have_count(0); passed("mobile navigation keyboard dismissal")
            passed("48 route/viewport overflow checks")
            # Same-state pixel repeatability check; not a claim of cross-platform visual parity.
            visit("/"); first = page.screenshot(animations="disabled"); second = page.screenshot(animations="disabled"); assert first == second; report["same_state_screenshot_sha256"] = sha256(first).hexdigest(); passed("same-state screenshot repeatability")
            page.get_by_role("button", name="Sign out", exact=True).click(); expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible(); passed("logout clears workspace")
            login("browser-employee"); visit("/assets"); expect(page.get_by_role("heading", name="Access restricted")).to_be_visible(); assert context.request.get(origin + "/api/v1/assets").status == 403
            visit(f"/transfers/{blocked['id']}"); expect(page.get_by_role("alert")).to_be_visible(); assert context.request.post(origin + f"/api/v1/transfers/{allowed['id']}/release", headers={"Origin": origin, "X-CSRF-Token": csrf()}).status in (403, 404)
            assert context.request.post(origin + "/api/v1/audit/verify", headers={"Origin": origin, "X-CSRF-Token": csrf()}).status == 403; passed("employee routes and direct APIs enforce RBAC and ownership")
            # Revoke the real session server-side, then trigger UI request expiry.
            assert context.request.post(origin + "/api/v1/auth/logout", headers={"Origin": origin, "X-CSRF-Token": csrf()}).status == 204
            visit("/"); expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible(); passed("revoked session cannot restore workspace")
            login("browser-analyst"); visit("/policies"); expect(page.get_by_role("button", name="Create policy version")).to_have_count(0)
            policy = context.request.get(origin + "/api/v1/policies/active").json()
            assert context.request.post(origin + "/api/v1/policies", data={"expected_version": policy["id"], "threshold": 1024}, headers={"Origin": origin, "X-CSRF-Token": csrf()}).status == 403; passed("analyst cannot modify policy")
            csp_violations = [e for e in console_errors if e.startswith("CSP violation") or "Content Security Policy" in e]
            report.update(csp_violations=len(csp_violations), console_errors=len(console_errors))
            assert not csp_violations, csp_violations
            assert not console_errors, console_errors
            assert not errors and not broken_assets, (errors, broken_assets)
            passed("zero CSP violations and zero console errors (HTTP error statuses from the negative checks excluded)")
            report.update(verdict="PASS", page_errors=len(errors), failed_assets=len(broken_assets))
        except Exception as error:
            report.update(verdict="FAIL", failure_type=type(error).__name__, completed_checks=len(report["checks"]))
            page.screenshot(path=str(state / "phase04-failure.png"), full_page=True)
            raise
        finally:
            (OUT / "browser-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            browser.close()


if __name__ == "__main__":
    main()
