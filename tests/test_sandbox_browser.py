"""Browser tests replay only reviewed, checked-in inert fixtures."""
import base64
import io
import os
from pathlib import Path

import pytest
from PIL import Image


FIXTURES = Path(__file__).parent / "fixtures" / "sandbox"
ORIGIN = "https://fixture.invalid"


@pytest.fixture(scope="module")
def chromium():
    playwright = pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as engine:
        executable = os.getenv("PHISHGUARD_FIXTURE_CHROMIUM")
        if not executable and not Path(engine.chromium.executable_path).exists():
            pytest.skip("Install Playwright Chromium or set PHISHGUARD_FIXTURE_CHROMIUM for fixture tests")
        browser = engine.chromium.launch(executable_path=executable, chromium_sandbox=True,
                  args=["--disable-background-networking", "--host-resolver-rules=MAP * ~NOTFOUND"])
        yield browser
        browser.close()


def resource(body: bytes, mime: str) -> dict:
    return {"status": 200, "headers": {"content-type": mime},
            "body": base64.b64encode(body).decode("ascii")}


def bundle(fixture: str, mode: str) -> dict:
    url = f"{ORIGIN}/{fixture}"
    resources = {url: resource((FIXTURES / fixture).read_bytes(), "text/html")}
    if fixture == "scrolling.html":
        resources[f"{ORIGIN}/gallery-tile.svg"] = resource(
            b'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
            b'<rect width="100" height="100" fill="#a53874"/></svg>', "image/svg+xml")
    if fixture == "rendering.html":
        resources[f"{ORIGIN}/result-icon.svg"] = resource(
            b'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
            b'<rect width="20" height="20" fill="#112233"/></svg>', "image/svg+xml")
    if fixture == "actions.html":
        resources[f"{ORIGIN}/details.js"] = resource(
            b'document.querySelector("#toggle").addEventListener("click", () => {'
            b'document.querySelector("#detail").hidden = false; '
            b'const form = document.querySelector("#sample-form"); '
            b'form.action = "https://forms.example.invalid/intermediate"; '
            b'form.action = "https://forms.example.invalid/final?calibration=private#sample"; });', "text/javascript")
    return {"url": url, "mode": mode, "resources": resources}


def replay(chromium, fixture: str, mode: str):
    from src.sandbox.browser import SafeInteractionEngine
    job = bundle(fixture, mode)
    return SafeInteractionEngine(chromium, job["url"], job["resources"]).analyze(mode)


def test_renderer_loss_closes_failed_context_and_allows_clean_replay(chromium, monkeypatch):
    from playwright.sync_api import Error
    from src.sandbox import browser as sandbox

    contexts_before = list(chromium.contexts)
    normal_capture = sandbox.JavaScriptBehaviorMonitor.viewport_capture
    crashed_pages = []
    def lose_renderer(monitor, clip=None):
        page = chromium.contexts[-1].pages[0]
        # This Chromium diagnostic is internal to the test browser. Navigation
        # and crash observation each have a deadline; no site code induces the loss.
        with page.expect_event("crash", timeout=4500) as loss:
            try:
                page.goto("chrome://crash", wait_until="commit", timeout=3000)
            except Error:
                pass  # Renderer loss aborts the diagnostic navigation.
        crashed_pages.append(loss.value)
        return normal_capture(monitor, clip)

    with monkeypatch.context() as patch:
        patch.setattr(sandbox.JavaScriptBehaviorMonitor, "viewport_capture", lose_renderer)
        with pytest.raises(Error):
            replay(chromium, "actions.html", "javascript-analysis")
    assert len(crashed_pages) == 1 and crashed_pages[0].is_closed()
    assert chromium.is_connected() and chromium.contexts == contexts_before
    result = replay(chromium, "actions.html", "javascript-analysis")
    assert result["screenshots"]["viewport"] and result["regions"]
    assert chromium.contexts == contexts_before


def test_offline_response_preserves_security_headers(chromium):
    from src.sandbox.browser import SafeInteractionEngine
    job = bundle("calibration.html", "javascript-analysis")
    job["resources"][job["url"]]["headers"].update({
        "permissions-policy": "camera=()", "x-frame-options": "DENY",
        "set-cookie": "fixture=1", "content-disposition": "inline",
    })
    context, page = SafeInteractionEngine(chromium, job["url"], job["resources"]).open_replay()
    try:
        headers = page.reload().all_headers()
        assert headers["permissions-policy"] == "camera=()" and headers["x-frame-options"] == "DENY"
        assert "content-disposition" not in headers and "set-cookie" not in headers
        assert context.cookies() == []
    finally:
        context.close()


def test_invisible_geometry_and_legitimate_controls(chromium):
    result = replay(chromium, "calibration.html", "interaction-scan")
    rows = {r["selector"]: r for r in result["regions"]}
    layer = rows["#screen"]
    assert layer["classification"] == "suspicious_interception"
    assert "#reference" in layer["intercepts"]
    assert layer["visual_mismatch"] and layer["actual_receiver"] == "#screen"
    assert layer["css"]["zIndex"] == "1200"
    assert len(layer["points"]) >= 5
    assert rows["#empty"]["classification"] == "invisible_receiver"
    assert rows["#decoration"]["classification"] == "non_receiving_hidden_element"
    assert rows["#decorated"]["classification"] == "visible_control"
    assert rows["#toggle"]["classification"] == "accessibility_control"
    assert rows["#away"]["offscreen"]
    assert rows["#label-sample"]["classification"] == "destination_mismatch"
    assert rows["#label-sample"]["visible_text"] == "https://label.invalid/"
    assert rows["#inactive-form"]["classification"] == "hidden_credential_form"
    assert rows["#calibration-frame"]["hidden"]
    child = rows["#frame-marker"]
    assert child["frame"] and child["effective_opacity"] == 0 and child["receives_pointer"]
    assert child["bbox"]["y"] > rows["#calibration-frame"]["bbox"]["y"]
    assert any(e["type"] == "iframe_inserted" for e in result["behavior"])
    assert any(e["type"] == "element_inserted" and e.get("selector") == "#decoration" for e in result["behavior"])
    assert {a["element_id"] for a in result["interactions"]} >= {layer["id"]}
    assert result["coverage"]["samples"] <= 1800


def test_synthetic_form_screenshot_change_and_blocked_navigation(chromium):
    result = replay(chromium, "actions.html", "analyze")
    actions = {a["selector"]: a for a in result["interactions"]}
    password = next(r for r in result["regions"] if r["tag"] == "input" and r["input_type"] == "password")
    assert password["attributes"]["name"] == "password" and "value" not in password["attributes"]
    assert "#purchase" not in actions
    submit = actions["#submit"]
    assert submit["synthetic_fields"] == 2
    assert submit["receiver_verified"] and submit["document_id"] != submit["baseline_document_id"]
    events = [e for e in result["behavior"] if e["action_id"] == submit["id"]]
    assert any(e["type"] == "form_submission" and e["credential"] and e["blocked"] and
               e["domain"] == "forms.example.invalid" and e["document_id"] == submit["document_id"] for e in events)
    assert all(e["blocked"] for e in result["network"] if e["action_id"])
    assert any(e["action_id"] == actions["#next"]["id"] and e["navigation"] and
               e["domain"] == "navigation.example.invalid" for e in result["network"])
    assert actions["#next"]["receiver_verified"]
    assert any(e["type"] == "click" and e["provenance"] == "cdp" and
               e["document_id"] == actions["#next"]["document_id"] for e in result["behavior"])
    assert actions["#toggle"]["changed_bbox"]
    for key in ("before", "after"):
        assert base64.b64decode(result["screenshots"][actions["#toggle"][key]]).startswith(b"\x89PNG")
    assert any(s["kind"] == "external" and "addEventListener" in s["code"] for s in result["scripts"])
    assert not any(s["source"].startswith("chrome-error:") for s in result["scripts"])
    assert any(e["type"] == "ui_mutation" and e["action_id"] == actions["#toggle"]["id"] for e in result["behavior"])
    edits = [e for e in result["behavior"] if e["type"] == "form_destination_change"]
    assert len(edits) == 1 and edits[0]["coalesced"] and edits[0]["form_selector"] == "#sample-form"
    assert edits[0]["from_url"] == "https://forms.example.invalid/completed"
    assert edits[0]["url"] == "https://forms.example.invalid/final" and edits[0]["document_sequence"] > 0
    # No raw form contents in the behavioral or network trace.
    assert "PhishGuardTest" not in str(result["behavior"] + result["network"])


def test_passive_mode_does_not_run_probes(chromium):
    result = replay(chromium, "actions.html", "javascript-analysis")
    assert result["interactions"] == []
    assert {"viewport", "annotated", "full_page"} == set(result["screenshots"])
    assert all(e["action_id"] is None for e in result["network"])
    assert result["performance"]["passive_screenshot_ms"] > 0


def test_screenshots_and_regions_include_delayed_component(chromium):
    result = replay(chromium, "rendering.html", "javascript-analysis")
    readiness = result["coverage"]["render_readiness"]
    assert readiness["status"] == "ready" and readiness["visible_content"]
    assert readiness["pending_images"] == readiness["failed_images"] == 0
    assert any(r["outcome"] == "cache_replay" and r["url"].endswith("/result-icon.svg") for r in result["network"])
    assert any(r["selector"] == "#result" for r in result["regions"])
    for view in ("viewport", "full_page"):
        with Image.open(io.BytesIO(base64.b64decode(result["screenshots"][view]))) as screenshot:
            pixels = screenshot.convert("RGB")
            assert pixels.getpixel((60, 60)) == (36, 104, 172)
            assert pixels.getpixel((75, 75)) == (17, 34, 51)
    assert result["interactions"] == []


@pytest.mark.parametrize(("navigation", "after_paint"), [
    (b'location.replace("/uncaptured")', False),
    (b'setTimeout(() => location.assign("/uncaptured"), 700)', True),
])
def test_uncaptured_navigation_records_available_page_evidence(chromium, navigation, after_paint):
    from src.sandbox.browser import SafeInteractionEngine

    url = f"{ORIGIN}/navigation.html"
    html = b'<!doctype html><head><script>' + navigation + b'</script></head><button id="saved">Saved component</button>'
    result = SafeInteractionEngine(chromium, url, {url: resource(html, "text/html")}).analyze("javascript-analysis")
    attempts = [r for r in result["network"] if r.get("url") == f"{ORIGIN}/uncaptured"]
    assert len(attempts) == 1 and attempts[0]["blocked"]
    assert attempts[0]["outcome"] == "blocked"
    readiness = result["coverage"]["render_readiness"]
    if after_paint:
        assert attempts[0]["navigation_suppressed"]
        assert result["final_url"] == url and any(r["selector"] == "#saved" for r in result["regions"])
        assert readiness["status"] == "partial" and "navigation_suppressed" in readiness["reasons"]
    else:
        assert attempts[0]["navigation_before_paint"] and not attempts[0].get("navigation_suppressed")
        assert "navigation_before_paint" in readiness["reasons"]
        assert readiness["status"] in {"partial", "timed_out"}
        if result["final_url"] == "chrome-error:":
            assert "browser_error_document" in readiness["reasons"]
            assert readiness["status"] == "partial" and readiness["waited_ms"] < readiness["timeout_ms"]
            assert not result["regions"] and not result["interactions"]


def test_missing_image_keeps_partial_evidence(chromium):
    from src.sandbox.browser import SafeInteractionEngine

    url = f"{ORIGIN}/image.html"
    html = b'<!doctype html><p>Photograph</p><img src="/absent.png" alt="Photograph" width="100" height="100">'
    result = SafeInteractionEngine(chromium, url, {url: resource(html, "text/html")}).analyze("javascript-analysis")
    readiness = result["coverage"]["render_readiness"]
    assert readiness["status"] == "partial" and readiness["failed_images"] == 1
    assert any(r["blocked"] and r["url"].endswith("/absent.png") for r in result["network"])


def test_empty_document_hits_readiness_deadline(chromium):
    from src.sandbox.browser import SafeInteractionEngine

    url = f"{ORIGIN}/empty.html"
    result = SafeInteractionEngine(chromium, url, {
        url: resource(b'<!doctype html><main aria-busy="true"></main>', "text/html")
    }).analyze("javascript-analysis")
    readiness = result["coverage"]["render_readiness"]
    assert readiness["status"] == "timed_out" and not readiness["visible_content"]
    assert "no_visible_content" in readiness["reasons"]
    assert 0 < readiness["waited_ms"] <= readiness["timeout_ms"] + 1500
    assert result["screenshots"]["viewport"]


def test_full_page_retains_virtualized_tiles_and_canonical_viewport(chromium):
    result = replay(chromium, "scrolling.html", "javascript-analysis")
    c = result["coverage"]
    full = c["full_page_readiness"]
    assert full["status"] == "ready", full
    assert full["visited_viewports"] > 1 and not c["full_page_clipped"]
    with Image.open(io.BytesIO(base64.b64decode(result["screenshots"]["full_page"]))) as image:
        assert image.size == (c["capture_width"], c["capture_height"]) == (1024, 3600)
        pixels = image.convert("RGB")
        for y in (1140, 3120):
            assert pixels.getpixel((60, y)) == (165, 56, 116)
    with Image.open(io.BytesIO(base64.b64decode(result["screenshots"]["viewport"]))) as image:
        assert image.size == (1024, 720)
    button = next(r for r in result["regions"] if r["selector"] == "#top")
    assert 0 <= button["bbox"]["y"] < 50 and result["interactions"] == []
    assert all(not n.get("url", "").endswith("gallery-tile.svg") for n in result["network"])


def test_full_page_reports_extent_when_document_exceeds_capture_limit(chromium):
    from src.sandbox.browser import SafeInteractionEngine

    url = f"{ORIGIN}/long.html"
    html = b'<!doctype html><body style="margin:0;height:24000px"><button>Beginning</button></body>'
    result = SafeInteractionEngine(chromium, url, {url: resource(html, "text/html")}).analyze("javascript-analysis")
    c = result["coverage"]
    full = c["full_page_readiness"]
    assert full["document_height"] == 24000 and full["status"] == "partial" and c["full_page_clipped"]
    with Image.open(io.BytesIO(base64.b64decode(result["screenshots"]["full_page"]))) as image:
        assert image.size == (c["capture_width"], c["capture_height"])
        assert 720 <= image.height < full["document_height"]


def test_unarchived_render_dependency_prevents_complete_capture_claim(chromium):
    from src.sandbox.browser import SafeInteractionEngine

    url = f"{ORIGIN}/styled.html"
    body = b'<!doctype html><link rel="stylesheet" href="/missing.css"><p>Fallback text</p>'
    result = SafeInteractionEngine(chromium, url, {url: resource(body, "text/html")}).analyze("javascript-analysis")
    for key in ("render_readiness", "full_page_readiness"):
        state = result["coverage"][key]
        assert state["status"] == "partial" and state["blocked_resources"]["stylesheet"] == 1
        assert "blocked_resources" in state["reasons"]


def test_resource_discovery_only_returns_passive_same_origin_assets(chromium):
    from src.sandbox.browser import SafeInteractionEngine

    url = f"{ORIGIN}/app.html"
    html = b'''<!doctype html><button id="probe">Load another script</button><script>
      const script = document.createElement('script');
      script.src = '/chunk.js?build=fixture'; document.head.append(script);
      fetch('/api/data');
      const crossOrigin = new Image(); crossOrigin.src = 'https://cdn.invalid/image.png';
      document.querySelector('#probe').onclick = () => {
        const dynamic = document.createElement('script');
        dynamic.src = '/after-click.js'; document.head.append(dynamic);
      };
    </script>'''
    result = SafeInteractionEngine(chromium, url, {url: resource(html, "text/html")}).analyze("analyze")
    assert result["_missing_resources"] == [{
        "url": ORIGIN + "/chunk.js?build=fixture", "method": "GET", "navigation": False, "resource_type": "script",
    }]
    assert any(event.get("action_id") and event.get("url", "").endswith("/after-click.js")
               for event in result["network"])


def test_delayed_map_open_components_and_document_generations(chromium):
    result = replay(chromium, "scopes.html", "interaction-scan")
    rows = result["regions"]
    passive = result["passive_changes"]
    assert passive["late_ms"] > passive["early_ms"] and passive["early_screenshot"] in result["screenshots"]
    assert any(c["type"] == "receiver_changed" and c["before_receiver"] == "#reference" and
               c["after_receiver"] == "#late-layer" for c in passive["changes"])
    assert any(c["type"] == "first_seen_late" and c["selector"] == "#late-layer" for c in passive["changes"])
    layer = next(r for r in rows if r["selector"] == "#late-layer")
    assert layer["passive_only"] and layer["classification"] == "suspicious_interception"
    shadows = [r for r in rows if r["shadow_path"]]
    assert {r["selector"] for r in shadows} == {"#first >>> #shared", "#second >>> #shared"}
    assert all(r["receives_pointer"] and r["actual_receiver"] == r["selector"] and r["passive_only"] for r in shadows)
    assert not any("closed-interior" in r["selector"] for r in rows)
    assert not {r["id"] for r in [layer, *shadows]}.intersection(a["element_id"] for a in result["interactions"])
    frames = [r for r in rows if r["frame"] and r["selector"] == "#shared"]
    assert len(frames) == 2 and len({r["document_id"] for r in frames}) == 2
    handlers = [s for s in result["scripts"] if s["kind"] == "handler" and s["selector"] == "#shared"]
    assert len({s["document_id"] for s in handlers}) == 3
    assert len({s["frame_key"] for s in handlers}) == 2
    assert any(e["type"] == "frame_navigation" and e.get("previous_document_id")
               and e["previous_document_id"] != e["document_id"] for e in result["behavior"])
    coverage = result["coverage"]
    assert coverage["open_shadow_roots"] == 2 and coverage["passive_checkpoints"] == 2
    assert coverage["samples"] <= 1800 and coverage["region_visits"] <= 240
    observed = [e["observation_index"] for e in result["behavior"] + result["network"]]
    assert len(observed) == len(set(observed))


def test_checkpoint_change_budget_and_ambiguous_selectors():
    from src.sandbox.browser import compare_checkpoints
    rows = [{"id": str(i), "document_id": "base", "frame_key": "main",
             "actual_receiver": f"#r{i}", "selector": f"#r{i}"} for i in range(90)]
    changes, limited = compare_checkpoints([], rows, early_complete={"base"}, late_complete={"base"})
    assert limited and len(changes) == 64 and all(row["passive_only"] for row in rows)
    duplicate = dict(rows[0], id="another")
    changes, limited = compare_checkpoints([], [rows[0], duplicate], early_complete={"base"}, late_complete={"base"})
    assert not changes and not limited and duplicate["passive_only"]
    for early, late in (([rows[0], duplicate], [rows[0]]), ([rows[0]], [rows[0], duplicate])):
        changes, _ = compare_checkpoints(early, late, early_complete={"base"}, late_complete={"base"})
        assert not changes and all(r["probe_exclusion"] == "ambiguous-selector" for r in late)


def test_dense_static_controls_preserve_early_replay_and_censor_claims(chromium):
    result = replay(chromium, "dense.html", "analyze")
    changes = result["passive_changes"]
    assert changes["truncated"] and changes["uncompared_early_replay_candidates"] > 0
    assert not any(c["type"] == "first_seen_late" for c in changes["changes"])
    assert any(c["type"] == "receiver_changed" and c["after_receiver"] == "#late" for c in changes["changes"])
    actions = {a["selector"]: a for a in result["interactions"]}
    assert actions["#static"]["early_replay_required"] and actions["#static"]["receiver_verified"]
    assert actions["#static"]["early_replay_ms"] <= changes["early_ms"]
    assert actions["#late"]["early_replay_required"] and actions["#late"]["status"] == "skipped"
    assert len(actions) <= 4 and result["coverage"]["samples"] <= 1800 and result["coverage"]["region_visits"] <= 240


def test_bounded_synthetic_marker_evidence(chromium):
    from src.sandbox.browser import SafeInteractionEngine
    job = bundle("actions.html", "analyze")
    scanner = SafeInteractionEngine(chromium, job["url"], job["resources"])
    context, page = scanner.open_replay()
    try:
        monitor = scanner.monitor
        monitor.action_id = "test-action"
        monitor.marker = "reviewed-fixture-canary"
        monitor.offline_action = True
        # Test with a constant diagnostic payload, independent of any form fields.
        page.evaluate("""async marker => {
            try { await fetch("/calibrate", {method:"POST", body:marker}); } catch (_) {}
        }""", monitor.marker)
        evidence = [e for e in monitor.network if e.get("action_id") == "test-action"]
        assert len(evidence) == 1 and evidence[0]["blocked"] and evidence[0]["synthetic_credential"]
        assert monitor.marker not in str(evidence)
        assert not monitor.carries_marker({"postData": "x" * 65536 + monitor.marker})
    finally:
        context.close()


@pytest.mark.skipif(os.environ.get("PHISHGUARD_TEST_DOCKER") != "1",
                    reason="Set PHISHGUARD_TEST_DOCKER=1 with the local worker image built")
def test_real_disposable_container_runs_reviewed_fixture(tmp_path):
    from src.sandbox.isolation import _docker, _run_worker
    job = bundle("actions.html", "analyze")
    report = _run_worker(_docker(str(tmp_path)), job)
    assert all(n["blocked"] for n in report["network"] if n.get("action_id"))
    assert any(e["type"] == "form_submission" and e["blocked"] for e in report["behavior"])
    assert report["screenshots"]["annotated"] and report["regions"]
