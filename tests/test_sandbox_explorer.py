"""Exercise the built same-origin React UI, authenticated API, and real fixture evidence."""
import base64
import os
from pathlib import Path
import socket
import threading
import time

import pytest
import uvicorn

from src.api.main import ROOT, create_app
from src.sandbox.analysis import build_report


def test_open_scan_and_inspect_click_receiver(tmp_path):
    if not (ROOT / "frontend/dist/index.html").exists():
        pytest.skip("Build the local explorer to run UI integration")
    api = pytest.importorskip("playwright.sync_api")
    token = "explorer-test"
    app = create_app(tmp_path, token=token, dispatch=False)
    with api.sync_playwright() as engine:
        executable = os.getenv("PHISHGUARD_FIXTURE_CHROMIUM")
        if not executable and not Path(engine.chromium.executable_path).exists():
            pytest.skip("A local Chromium installation is required for UI integration")
        with engine.chromium.launch(executable_path=executable, chromium_sandbox=True,
                args=["--disable-background-networking",
                      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"]) as browser:
            from src.sandbox.browser import SafeInteractionEngine
            fixture = ROOT / "tests/fixtures/sandbox/calibration.html"
            url = "https://fixture.invalid/calibration.html"
            # Supply only the checked-in fixture. Browser requests resolve from this in-memory archive.
            raw = SafeInteractionEngine(browser, url, {url: {
                "headers": {"content-type": "text/html"}, "status": 200,
                "body": base64.b64encode(fixture.read_bytes()).decode(),
            }}).analyze("interaction-scan")
            report = build_report(raw)
            assert report["scores"]["interaction_risk"] >= 65
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                sock.listen()
                server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
                thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
                thread.start()
                try:
                    deadline = time.monotonic() + 10
                    while not server.started and time.monotonic() < deadline:
                        time.sleep(0.02)
                    assert server.started
                    page = browser.new_page(viewport={"width": 1280, "height": 860})
                    # Hold the first screenshot decode across a paint to check loading feedback.
                    page.add_init_script("""{
                        const decode = HTMLImageElement.prototype.decode;
                        let first = true;
                        HTMLImageElement.prototype.decode = async function () {
                            if (this.src.startsWith('blob:') && first) {
                                first = false;
                                document.documentElement.dataset.decoding = "waiting";
                                await new Promise(resolve => document.addEventListener("fixture-decode-release", resolve, {once:true}));
                            }
                            return decode.call(this);
                        };
                    }""")
                    errors = []
                    artifacts = []
                    page.on("pageerror", lambda exc: errors.append(str(exc)))
                    page.on("request", lambda req: artifacts.append(req.url) if "/screenshot/" in req.url else None)
                    page.goto(f"http://127.0.0.1:{sock.getsockname()[1]}/explorer/")
                    page.get_by_label("Website URL").fill(url)
                    page.get_by_label("Sandbox access token").fill(token)
                    page.get_by_label("Analysis mode").select_option("interaction-scan")
                    with page.expect_response(lambda r: r.url.endswith("/interaction-scan") and r.status == 202) as response:
                        page.get_by_role("button", name="Start analysis").click()
                    job = response.value.json()["analysis_id"]
                    assert app.state.store.claim() == job
                    app.state.store.complete(job, report)
                    api.expect(page.locator("html")).to_have_attribute("data-decoding", "waiting")
                    api.expect(page.get_by_text("Loading capture…", exact=True)).to_be_visible()
                    api.expect(page.get_by_role("button", name="Inspect #screen", exact=True)).to_have_count(0)
                    page.locator("html").dispatch_event("fixture-decode-release", {"bubbles": True})
                    page.get_by_role("button", name="Inspect #screen", exact=True).click()
                    api.expect(page.locator(".detail .selector")).to_have_text("#screen")
                    api.expect(page.locator(".detail")).to_contain_text("#reference")
                    action = next(item for item in report["interactions"] if item["selector"] == "#screen")
                    assert all("view=" + action["before"] not in address for address in artifacts)
                    page.get_by_text("Interaction " + action["id"], exact=True).click()
                    api.expect(page.get_by_alt_text("Captured website, " + action["before"])).to_be_visible()
                    api.expect(page.get_by_alt_text("Captured website, " + action["after"])).to_be_visible()
                    page.get_by_label("DOM overlay layer").select_option("Transparent elements")
                    assert page.get_by_role("button", name="Inspect #away", exact=True).count() == 0
                    page.get_by_role("button", name="Click receivers", exact=True).click()
                    assert page.locator(".point").count() > 0
                    page.get_by_role("button", name="Network", exact=True).click()
                    api.expect(page.get_by_role("heading", name="Network activity")).to_be_visible()
                    page.get_by_role("button", name="Annotated", exact=True).click()
                    api.expect(page.get_by_alt_text("Captured website, annotated")).to_be_visible()
                    replay_button = page.get_by_role("button", name="Replay capture", exact=True)
                    api.expect(replay_button).to_have_count(0)

                    # Exercise a retained capture and a retry without making an outbound capture.
                    # The second job still uses real polling, artifact serving and terminal storage.
                    def retained(route):
                        original = route.fetch()
                        data = original.json()
                        data["report"]["replay_available"] = True
                        data["report"]["coverage"]["render_readiness"] = {
                            "status": "timed_out", "reasons": ["busy_components", "fonts_loading"]}
                        route.fulfill(response=original, json=data)

                    submissions = []
                    def enqueue_replay(route):
                        submissions.append(route.request)
                        if len(submissions) == 1:
                            route.fulfill(status=429, json={"detail": "The sandbox queue is full."})
                            return
                        job_id = app.state.store.enqueue(url, "interaction-scan")
                        route.fulfill(status=202, json={"analysis_id": job_id, "status": "queued"})

                    page.route("**/api/sandbox/report/" + job, retained)
                    page.route("**/api/sandbox/replay/" + job, enqueue_replay)
                    page.get_by_role("button", name="Open workspace").click()
                    page.get_by_role("button", name="Open report").click()
                    page.get_by_label("Analysis ID").fill(job)
                    page.get_by_role("button", name="Load report").click()
                    api.expect(page.get_by_role("note")).to_contain_text("Capture wait limit reached.")
                    api.expect(page.get_by_role("note")).to_contain_text("Fonts were still loading.")
                    api.expect(page.get_by_alt_text("Captured website, viewport")).to_be_visible()
                    replay_button.click()
                    api.expect(page.get_by_role("alert")).to_contain_text("sandbox queue is full")
                    with page.expect_response(lambda r: r.url.endswith("/replay/" + job) and r.status == 202) as replay:
                        replay_button.click()
                    replay_id = replay.value.json()["analysis_id"]
                    assert all(r.method == "POST" and r.post_data is None for r in submissions)
                    assert all(r.headers["authorization"] == "Bearer " + token for r in submissions)
                    assert app.state.store.claim() == replay_id
                    # Exercise the pre-evolution report shape on the existing screenshot endpoints.
                    older = {k:v for k,v in report.items() if k not in {
                        "attack_sequences", "passive_changes", "behavior_profile", "performance", "model_evidence"}}
                    older["coverage"] = {k: v for k, v in report["coverage"].items() if k != "render_readiness"}
                    app.state.store.complete(replay_id, {**older, "capture": {"replayed_from": job}})
                    api.expect(page.get_by_text("Replayed from", exact=False)).to_contain_text(job)
                    api.expect(page.get_by_role("alert")).to_have_count(0)
                    api.expect(page.locator("summary", has_text="Behavior fingerprint")).to_have_count(0)
                    api.expect(page.get_by_role("button", name="Inspect #screen", exact=True)).to_be_visible()
                    api.expect(page.get_by_role("note")).to_have_count(0)

                    # Historical report shape of a blocked main-frame navigation; no external site involved.
                    historical_job = app.state.store.enqueue(url, "interaction-scan")
                    assert app.state.store.claim() == historical_job
                    app.state.store.complete(historical_job, {**older, "regions": [], "final_url": "chrome-error:",
                        "network": [{"navigation": True, "blocked": True, "frame_key": "main", "action_id": None}]})
                    page.get_by_role("button", name="Open workspace").click()
                    page.get_by_label("Analysis ID").fill(historical_job)
                    page.get_by_role("button", name="Load report").click()
                    unavailable = page.get_by_role("region", name="Website screenshot unavailable")
                    api.expect(unavailable).to_contain_text("Offline replay blocked a page navigation.")
                    api.expect(unavailable.locator("img")).to_have_count(0)
                    assert not any(historical_job in address for address in artifacts)
                    unavailable.get_by_text("Show recorded browser screenshot", exact=True).click()
                    api.expect(unavailable.get_by_alt_text("Recorded Chromium error page, viewport")).to_be_visible()
                    api.expect(page.locator(".box, .point")).to_have_count(0)
                    unavailable.get_by_role("button", name="View network activity").click()
                    api.expect(page.get_by_role("heading", name="Network activity")).to_be_visible()
                    api.expect(page.get_by_role("button", name="Network", exact=True)).to_be_focused()

                    # A newer synthetic report has a confirmed prepaint request and an earlier stored observation.
                    modern_job = app.state.store.enqueue(url, "interaction-scan")
                    assert app.state.store.claim() == modern_job
                    destination = "https://fixture.invalid/another-document"
                    app.state.store.complete(modern_job, {
                        **older, "regions": [], "final_url": "chrome-error:",
                        "coverage": {**older["coverage"], "render_readiness": {
                            "status": "timed_out", "browser_error_document": True, "prepaint_navigations": 1}},
                        "network": [
                            {"blocked": True, "navigation": True, "frame_key": "main", "url": destination,
                             "navigation_before_paint": True, "action_id": None},
                            {"blocked": True, "navigation": True, "frame_key": "main", "url": url, "action_id": "probe"}],
                        "screenshots": {**older["screenshots"], "initial": older["screenshots"]["viewport"]},
                    })
                    page.get_by_role("button", name="Open workspace").click()
                    page.get_by_label("Analysis ID").fill(modern_job)
                    page.get_by_role("button", name="Load report").click()
                    api.expect(unavailable).to_contain_text("before displaying any content")
                    api.expect(unavailable.locator("code")).to_have_text(destination)
                    api.expect(unavailable.get_by_role("link")).to_have_count(0)
                    page.get_by_role("button", name="Annotated", exact=True).click()
                    api.expect(unavailable.locator("img")).to_have_count(0)
                    assert not any(modern_job in address for address in artifacts)
                    page.get_by_role("button", name="Original", exact=True).click()
                    page.get_by_label("Screenshot extent").select_option("initial")
                    api.expect(page.get_by_alt_text("Captured website, initial")).to_be_visible()
                    api.expect(unavailable).to_have_count(0)

                    # Inspect a second, genuinely observed report with a delayed change and sibling frames.
                    scoped_url = "https://fixture.invalid/scopes.html"
                    scoped = build_report(SafeInteractionEngine(browser, scoped_url, {scoped_url: {
                        "headers": {"content-type": "text/html"}, "status": 200,
                        "body": base64.b64encode(fixture.with_name("scopes.html").read_bytes()).decode(),
                    }}).analyze("javascript-analysis"))
                    scoped_job = app.state.store.enqueue(scoped_url, "javascript-analysis")
                    assert app.state.store.claim() == scoped_job
                    app.state.store.complete(scoped_job, scoped)
                    page.get_by_role("button", name="Open workspace").click()
                    page.get_by_label("Analysis ID").fill(scoped_job)
                    page.get_by_role("button", name="Load report").click()
                    sequence = next(s for s in scoped["attack_sequences"] if s["attribution"] == "passive_observation")
                    page.locator("summary", has_text="Reconstructed sequences").click()
                    api.expect(page.get_by_role("heading", name=sequence["title"])).to_be_visible()
                    for stage in sequence["stages"]:
                        api.expect(page.get_by_text(stage["label"], exact=True)).to_be_visible()
                    first_evidence = page.locator(".sequences summary", has_text="Evidence ").first
                    first_evidence.click()
                    api.expect(page.locator(".sequences")).to_contain_text("receiver changed")
                    page.get_by_role("button", name="Inspect attributed region").first.click()
                    api.expect(page.locator(".detail .selector")).to_have_text("#late-layer")
                    frame = next(row["frame_key"] for row in scoped["regions"] if row["selector"] == "#shared")
                    page.get_by_label("Filter by frame").select_option(frame)
                    api.expect(page.locator(".regionList code", has_text="#shared")).to_have_count(1)
                    page.locator(".regionList button").first.click()
                    api.expect(page.locator(".detail")).to_contain_text(frame)
                    page.get_by_text("Capture coverage", exact=True).click()
                    api.expect(page.get_by_role("heading", name="Passive checkpoints")).to_be_visible()
                    api.expect(page.get_by_role("table", name="Counts of sampled coordinates", exact=False).locator("td")).to_have_count(48)
                    page.get_by_text("Behavior fingerprint", exact=True).click()
                    api.expect(page.get_by_text(scoped["behavior_profile"]["digest"], exact=True)).to_be_visible()
                    page.get_by_text("Analysis measurements", exact=True).click()
                    api.expect(page.get_by_text("correlation ms", exact=True)).to_be_visible()
                    page.get_by_role("button", name="Original", exact=True).click()
                    page.get_by_label("Screenshot extent").select_option("initial")
                    api.expect(page.get_by_alt_text("Captured website, initial")).to_be_visible()
                    page.route("**/screenshot/*?view=full_page",
                               lambda route: route.fulfill(content_type="image/png", body=b"invalid fixture image"))
                    page.get_by_label("Screenshot extent").select_option("full_page")
                    api.expect(page.get_by_text("The screenshot could not be decoded.")).to_be_visible()
                    api.expect(page.locator(".canvas img")).to_have_count(0)

                    # Open a saved tall capture through its local report link. An omitted
                    # stylesheet leaves real pixels and a useful partial-capture notice.
                    tall_url = "https://fixture.invalid/tall.html"
                    tall_html = b'<!doctype html><link rel="stylesheet" href="/missing.css"><body style="margin:0;height:1560px"><button>Top</button></body>'
                    tall = build_report(SafeInteractionEngine(browser, tall_url, {tall_url: {
                        "headers": {"content-type": "text/html"}, "status": 200,
                        "body": base64.b64encode(tall_html).decode(),
                    }}).analyze("javascript-analysis"))
                    tall_job = app.state.store.enqueue(tall_url, "javascript-analysis")
                    assert app.state.store.claim() == tall_job
                    app.state.store.complete(tall_job, tall)
                    page.unroute("**/screenshot/*?view=full_page")
                    page = browser.new_page()
                    page.goto(f"http://127.0.0.1:{sock.getsockname()[1]}/explorer/#report={tall_job}")
                    api.expect(page.get_by_label("Analysis ID")).to_have_value(tall_job)
                    page.get_by_label("Sandbox access token").fill(token)
                    page.get_by_role("button", name="Load report").click()
                    api.expect(page.get_by_label("Screenshot extent")).to_have_value("full_page")
                    api.expect(page.locator(".canvasHeader")).to_contain_text("1024 × 1560 full page")
                    api.expect(page.get_by_role("note")).to_contain_text("stylesheets")
                    full_image = page.get_by_alt_text("Captured website, full page")
                    api.expect(full_image).to_be_visible()
                    assert full_image.evaluate("img => img.naturalHeight") == 1560
                    assert page.locator(".canvas").evaluate("el => el.scrollHeight <= el.clientHeight + 1")
                    with page.expect_download() as download:
                        page.get_by_role("link", name="Save full-page PNG").click()
                    assert download.value.path().read_bytes() == app.state.store.image(tall_job, "full_page")
                    page.get_by_role("button", name="DOM overlay", exact=True).click()
                    api.expect(page.locator(".canvasHeader")).to_contain_text("1024 × 720 viewport")
                    api.expect(page.get_by_alt_text("Captured website, viewport")).to_be_visible()
                    assert errors == []
                finally:
                    server.should_exit = True
                    thread.join(timeout=8)
                    assert not thread.is_alive()
