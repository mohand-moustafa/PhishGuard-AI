"""Local evidence tests. Scripts here are parser inputs, never evaluated."""
import base64
import csv
import io
import json
import math
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

from src.sandbox.analysis import build_report
from src.sandbox.analysis_features import model_features
from src.sandbox.analysis_js import JavaScriptStaticAnalyzer
from src.sandbox.analysis_model import predict_url
from src.sandbox.analysis_vision import PhishGuardVisionAnalyzer

PAGE = "https://fixture.example/"
DEST = "https://sink.invalid/blocked"
BASELINE = {"probability": 0.1, "model": "fixture", "status": "available", "label": "legitimate"}
DOC = {"frame_key": "main", "document_id": "baseline:main@1"}
REPLAY = {"frame_key": "main", "document_id": "a1:main@1"}
ACTION = {**REPLAY, "baseline_document_id": DOC["document_id"], "receiver_verified": True,
          "status": "tested", "id": "a1", "element_id": "r1"}


def row(id="r1", **values):
    return dict({**DOC, "id": id, "selector": "#" + id, "tag": "button", "frame_url": PAGE,
                 "bbox": {"x": 0, "y": 0, "width": 100, "height": 40},
                 "hidden": False, "classification": "visible_control", "intercepts": []}, **values)


def sample(**values):
    return dict({"url": PAGE, "final_url": PAGE, "regions": [row()], "behavior": [], "network": [],
                 "screenshots": {}, "interactions": [dict(ACTION)]}, **values)


def report(**values):
    return build_report(sample(**values), model_prediction=BASELINE)


def test_no_script_comments_or_literal_strings_classified_as_calls():
    scripts = [{"code": 'const text = "eval(1)"; /*window.open(2)*/\n atob("AA==");',
                "kind": "inline", "source": PAGE, "selector": "#s"}]
    found, coverage = JavaScriptStaticAnalyzer().analyze(scripts, [])
    assert coverage["status"] == "complete"
    assert [(r["rule_id"], r["line"]) for r in found] == [("js.decode", 2)]
    assert found[0]["severity"] == "informational"


def test_viewport_coverage_counts_unique_sampled_coordinates():
    corners = [{"x": 0, "y": 0}, {"x": 79.5, "y": 59.5}]
    out = report(viewport={"width": 80, "height": 60},
                 regions=[row(points=corners), row("b", points=corners[:1]),
                          row("off", points=[{"x": 80, "y": 0}, {"x": -1, "y": 2}])])
    grid = out["coverage"]["viewport_sampling"]
    assert grid["distinct_positions"] == 2 and grid["regions_without_viewport_samples"] == 1
    assert grid["cells"][0][0] == grid["cells"][5][7] == 1
    assert sum(map(sum, grid["cells"])) == 2


def test_static_analysis_links_element_and_reports_budget():
    engine = JavaScriptStaticAnalyzer()
    engine.max_scripts = 1
    findings, coverage = engine.analyze([{**DOC, "code": 'window.open("about:blank")', "selector": "#r1"},
                                        {"code": "debugger;"}], [{
        **DOC, "type": "popup_attempt", "selector": "#r1", "id": "evt-1"
    }])
    assert coverage["limited"] and findings[0]["related_events"] == ["evt-1"]


def test_accessibility_and_nonreceiving_transparency_do_not_score():
    rows = [row(hidden=True, classification="accessibility_control"),
            row("label", tag="span", hidden=True, classification="non_receiving_hidden_element")]
    out = report(regions=rows)
    assert out["transparent_elements"] == ["r1", "label"]
    assert out["scores"]["interaction_risk"] == 0 and not out["findings"]


def test_hidden_layer_and_external_form_evidence_only_join_same_action():
    overlay = row(hidden=True, intercepts=["#login"], visual_mismatch=True,
                  classification="suspicious_interception")
    form = row("form", tag="form", hidden=True, credential=True, destination=DEST,
               classification="hidden_credential_form")
    submitted = {**REPLAY, "provenance": "instrumentation", "trigger_phase": "click",
                 "type": "form_submission", "credential": True, "element_id": "r1",
                 "action_id": "a1", "selector": "#form", "frame_url": PAGE, "url": DEST, "blocked": True}
    scripts = [{**DOC, "source": PAGE, "selector": "#r1", "code": "form.requestSubmit()", "kind": "handler"}]
    result = report(regions=[overlay, form], scripts=scripts, behavior=[submitted, submitted])
    indexed = [f for f in result["findings"] if f["rule_id"] == "credentials.external-attempt"]
    assert len(indexed) == 1
    assert {"r1", "form", "js-1", "event-1"} <= set(indexed[0]["evidence_ids"])
    assert indexed[0]["severity"] == "critical" and indexed[0]["action_id"] == "a1"
    assert result["scores"]["overall_website_risk"] == 94
    assert result["regions"][0]["confirmed_mechanism"] == "deceptive_receiver_with_blocked_external_password_form"
    assert result["final_phishing_probability"] == 0.1
    unrelated = report(regions=[overlay, form], behavior=[{**submitted, "action_id": "elsewhere"}])
    assert unrelated["scores"]["credential_theft_risk"] == 43


def test_password_read_and_analytics_post_do_not_establish_credential_transfer():
    reading = {"type": "credential_access", "element_id": "r1", "action_id": "a1"}
    network = {"type": "request", "method": "POST", "url": DEST, "element_id": "r1", "action_id": "a1",
               "blocked": True, "provenance": "playwright", "resource_type": "fetch"}
    assert report(network=[network], behavior=[reading])["scores"]["credential_theft_risk"] == 0
    out = report(network=[dict(network, synthetic_credential=True)])
    assert out["scores"]["credential_theft_risk"] >= 85
    fake = report(network=[dict(network, synthetic_credential=True, provenance="instrumentation")])
    assert fake["scores"]["credential_theft_risk"] == 0


def test_link_discrepancy_requires_visible_host_and_respects_registrable_domain():
    offsite = row(tag="a", visible_text="https://brand.example.com", destination=DEST)
    local = dict(offsite, destination="https://sso.example.com")
    assert report(regions=[offsite])["scores"]["visual_deception"] == 44
    assert report(regions=[local])["scores"]["visual_deception"] < 10
    assert report(regions=[dict(offsite, visible_text="", text="https://brand.example.com")])["findings"] == []


def test_local_reputation_broker_redirect_and_timeline(tmp_path, monkeypatch):
    source = tmp_path / "flagged.txt"
    source.write_text("sink.invalid\n")
    monkeypatch.setenv("PHISHGUARD_FLAGGED_DOMAINS", str(source))
    out = report(broker_trace=[{"url": PAGE, "redirect": "/elsewhere", "timestamp": 1770000000}],
                 network=[{"type": "request", "url": DEST, "domain": "sink.invalid"}])
    assert out["redirect_findings"] == ["net-1"]
    assert out["network"][0]["redirect"] == PAGE + "elsewhere"
    assert out["reputation_status"] == "available" and len(out["network_findings"]) == 1
    assert {e["id"] for e in out["evidence_timeline"]} == {"net-1", "net-2"}


def test_trained_feature_values_match_saved_rows_without_network():
    root = Path(__file__).resolve().parents[1]
    selected = json.loads((root / "models/feature_groups.json").read_text())["feature_sets"]["full"]
    path = root / "data/processed/engineered_dataset.csv"
    with path.open(encoding="utf-8") as source:
        reader = csv.DictReader(source)
        for _ in range(12):
            row = next(reader)
            values = model_features(row["url"])
            for name in selected:
                if name == "young_brand_impersonation":
                    assert values[name] == 0  # Offline registration age is unknown.
                else:
                    assert values[name] == pytest.approx(float(row[name]), abs=0.00001)


def test_real_stored_xgboost_and_logistic_shap_reconstruct_probability():
    model = predict_url(PAGE)
    assert model["status"] == "available", model
    shap = model["shap"]
    reconstructed = 1 / (1 + math.exp(-(shap["base_value"] + sum(shap["values"].values()))))
    assert reconstructed == pytest.approx(model["probability"], abs=1e-5)
    assert len(shap["values"]) == 25
    assert model["threshold"] == 0.45


@pytest.mark.parametrize("coverage", [
    {},
    {"render_readiness": {"status": "partial", "visible_content": True, "reasons": ["navigation_suppressed"]}},
])
def test_vision_pixels_and_local_ocr(coverage):
    pytest.importorskip("rapidocr_onnxruntime")
    image = Image.new("RGB", (500, 340), "white")
    pen = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=38)
    pen.rectangle((30, 30, 420, 130), outline="black", width=3)
    pen.text((65, 50), "Sign in", fill="black", font=font)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    vision = PhishGuardVisionAnalyzer().analyze(
        sample(screenshots={"viewport": base64.b64encode(buffer.getvalue()).decode("ascii")}, coverage=coverage))
    assert vision["backends"]["pixels"] == "available" and vision["segments"]
    assert vision["backends"]["ocr"] == "available"
    assert any("sign in" in line["keywords"] for line in vision["ocr_lines"])
    assert vision["backends"]["yolo"] == "unconfigured"


@pytest.mark.parametrize(("coverage", "final_url"), [
    ({"render_readiness": {"browser_error_document": True, "visible_content": True}}, PAGE),
    ({}, "chrome-error:"),
])
def test_internal_error_viewport_is_retained_without_website_pixel_analysis(monkeypatch, coverage, final_url):
    from src.sandbox import analysis_vision

    def unexpected_decode(_):
        pytest.fail("Chromium's internal document reached website pixel analysis")

    monkeypatch.setattr(analysis_vision, "_image", unexpected_decode)
    png = io.BytesIO()
    Image.new("RGB", (20, 12), "white").save(png, format="PNG")
    artifact = base64.b64encode(png.getvalue()).decode("ascii")
    attempted = {"url": DEST, "method": "GET", "type": "request", "blocked": True,
                 "navigation": True, "provenance": "playwright", "outcome": "blocked"}
    result = report(regions=[], interactions=[], coverage=coverage, final_url=final_url,
                    screenshots={"viewport": artifact}, network=[attempted])
    vision = result["vision"]
    assert vision["image_status"] == "browser_error_document"
    assert set(vision["backends"].values()) == {"not_run"}
    assert vision["segments"] == vision["ocr_lines"] == vision["brands"] == []
    assert result["brand_impersonation_findings"] == []
    assert result["screenshots"]["viewport"] == artifact and result["network"][0]["blocked"]


def test_vision_rejects_unbounded_or_invalid_viewport():
    image = Image.new("1", (2500, 8))
    file = io.BytesIO()
    image.save(file, format="PNG")
    for value in ("broken", base64.b64encode(file.getvalue()).decode("ascii")):
        out = PhishGuardVisionAnalyzer().analyze(sample(screenshots={"viewport": value}))
        assert out["image_status"] == "invalid_or_unsupported"


def test_static_listener_literal_joins_external_script_to_unique_dom_element():
    script = {**DOC, "source": PAGE + "ui.js", "kind": "external", "code":
              'document.querySelector("#r1").addEventListener("click", () => window.open("about:blank"));'}
    report_data = report(scripts=[script], behavior=[{**DOC, "type": "listener_registration",
                         "selector": "#r1", "frame_url": PAGE}])
    found = {f["rule_id"]: f for f in report_data["javascript_findings"]}
    assert found["js.listener"]["related_events"] == ["event-1"]
    assert found["js.popup"]["element_id"] == "r1"


def test_logo_box_unletterboxing_domain_boundary_and_clip_corroboration(tmp_path, monkeypatch):
    import numpy as np
    from src.sandbox import analysis_vision
    from src.sandbox.analysis import InteractionThreatCorrelator

    class Net:
        def setInput(self, blob):
            assert blob.shape == (1, 3, 640, 640)

        def forward(self):
            return np.array([[[320], [320], [100], [50], [0.92]]], dtype="float32")

    labels = [{"brand": "Fixture", "domains": ["fixture.example"]}]
    monkeypatch.setattr(analysis_vision, "_logo_model", lambda _: (Net(), labels))
    monkeypatch.setattr(analysis_vision, "_verify_logo", lambda *_: 0.95)
    (tmp_path / "clip").mkdir()
    image = Image.new("RGB", (640, 320))
    brands = analysis_vision._logos(image, "https://fixture.example.invalid", [], tmp_path, {})
    assert brands[0]["bbox"] == {"x": 270, "y": 135, "width": 100, "height": 50}
    assert brands[0]["domain_mismatch"] and brands[0]["clip_similarity"] == 0.95
    assert not analysis_vision._logos(image, "https://www.fixture.example", [], tmp_path, {})[0]["domain_mismatch"]
    result = InteractionThreatCorrelator().correlate(sample(), [], {"brands": brands, "ocr_lines": []}, BASELINE)
    assert result["findings"][0]["rule_id"] == "visual.brand-domain"


@pytest.mark.parametrize(("status", "phase"), [("receiver_changed", "click"), ("tested", "synthetic_input")])
def test_probe_without_confirmed_click_keeps_transfer_evidence_unattributed(status, phase):
    event = {"type": "request", "element_id": "r1", "action_id": "a1", "trigger_phase": phase,
             "method": "POST", "resource_type": "fetch", "url": DEST, "blocked": True,
             "provenance": "playwright", "synthetic_credential": True}
    out = report(interactions=[{"id": "a1", "element_id": "r1", "status": status}], network=[event])
    assert out["findings"][0]["rule_id"] == "credentials.synthetic-transfer"
    assert out["findings"][0]["element_id"] is None
    assert out["regions"][0]["risk_score"] == 0
    assert out["network"][0]["attempted_element_id"] == "r1"
    assert out["network"][0]["element_id"] is None


@pytest.mark.parametrize(("frame", "document"), [
    ("main/frame-1", "a1:main/frame-1@1"),  # Simultaneous submission in a child frame
    ("main", "a1:main@2"),                   # Same URL after document replacement
    (None, None),                            # Historical or unattributable event
])
def test_form_in_another_document_is_not_attributed_to_parent_click(frame, document):
    overlay = row(hidden=True, intercepts=["#login"], visual_mismatch=True, classification="suspicious_interception")
    form = row("f", selector="#form", tag="form", credential=True, destination=DEST,
               frame_key="main/frame-1", document_id="baseline:main/frame-1@1")
    submit = {"frame_key": frame, "document_id": document, "frame_url": PAGE, "action_id": "a1",
              "element_id": "r1", "trigger_phase": "click", "type": "form_submission", "url": DEST,
              "blocked": True, "credential": True, "selector": "#form", "provenance": "instrumentation"}
    out = report(regions=[overlay, form], behavior=[submit])
    assert out["scores"]["credential_theft_risk"] == 35
    assert not out["regions"][0]["confirmed_mechanism"]
    assert out["attack_sequences"][0]["element_id"] is None
    assert out["attack_sequences"][0]["attribution"] == "action_only"
    assert out["behavior"][0]["attempted_element_id"] == "r1"


def test_duplicate_selectors_and_external_scripts_are_document_scoped():
    child = {"frame_key": "main/frame-1", "document_id": "baseline:main/frame-1@1"}
    sibling = {"frame_key": "main/frame-2", "document_id": "baseline:main/frame-2@1"}
    script = {**child, "source": PAGE + "ui.js", "kind": "external",
              "code": 'document.querySelector("#login").addEventListener("click", () => window.open("about:blank"));'}
    rows = [row("a", selector="#login", **sibling), row("b", selector="#login", **child)]
    filtered = report(regions=rows, scripts=[script, {**script, "document_id": None}],
                      behavior=[{**sibling, "type": "listener_registration", "selector": "#login"},
                                {**child, "type": "listener_registration", "selector": "#login"}])
    found = [f for f in filtered["javascript_findings"] if f["rule_id"] == "js.listener"]
    assert [(f["element_id"], f["related_events"]) for f in found] == [("b", ["event-2"]), (None, [])]


def test_cdp_handler_source_location_can_associate_named_callback():
    script = {**DOC, "kind": "external", "source": PAGE + "main.js",
              "code": 'function run(event) {\nwindow.open("about:blank");\n}\n'}
    handlers = [{"source": script["source"], "line": 1, "column": 12, "event": "click"}]
    regions = [row(handler_locations=handlers), row("next", handler_locations=[
               {**handlers[0], "line": 3}])]
    finding = report(regions=regions, scripts=[script])["javascript_findings"][0]
    assert finding["element_id"] == "r1" and finding["association"] == "cdp_listener_location"


def test_external_marker_sequence_stages_keep_collection_order_and_provenance():
    action_event = {**REPLAY, "element_id": "r1", "action_id": "a1", "trigger_phase": "click"}
    click = {**action_event, "type": "click", "trusted": True, "provenance": "instrumentation",
             "observation_index": 4, "timestamp": "2026-01-01T00:01:01Z"}
    request = {**action_event, "type": "request", "provenance": "playwright", "url": DEST,
               "resource_type": "fetch", "blocked": True, "synthetic_credential": True, "observation_index": 2,
               "timestamp": "2026-01-01T00:01:02Z"}
    result = report(behavior=[click], network=[request], performance={"worker_ms": 31})
    sequence = result["attack_sequences"][0]
    assert sequence["baseline_document_id"] == DOC["document_id"] and sequence["document_id"] == REPLAY["document_id"]
    assert [s["stage"] for s in sequence["stages"]] == ["receiver", "request", "click"]
    assert sequence["stages"][1]["provenance"] == ["playwright"]
    assert sequence["stages"][1]["evidence_ids"] == ["net-1"]
    assert sequence["uncertainty"] and result["performance"]["worker_ms"] == 31
    assert all(result["performance"][k] >= 0 for k in ["javascript_ms", "vision_ms", "correlation_ms"])


def test_ocr_overlaps_visible_control_and_separately_identifies_verified_cover():
    from src.sandbox.analysis_vision import _regions_at
    bbox = {"x": 2, "y": 3, "width": 46, "height": 19}
    background = row("label", selector="#submit")
    cover = row("cover", hidden=True, receives_pointer=True, intercepts=["#submit"])
    noise = row("noise", bbox={"x": 24, "y": 12, "width": 2, "height": 3})
    other_frame = row("wrong", hidden=True, receives_pointer=True, intercepts=["#submit"],
                      frame_key="main/frame-1", document_id="baseline:main/frame-1@1")
    assert _regions_at(bbox, [background, cover, noise, other_frame]) == {
        "element_ids": ["label"], "occluding_receiver_ids": ["cover"]}


def test_parser_distinguishes_browser_evaluator_and_benign_library_names():
    records, _ = JavaScriptStaticAnalyzer().analyze([{
        "source": PAGE, "code": 'calculator.eval("one"); var data = new FormData(form);'
    }], [])
    assert [f["rule_id"] for f in records] == ["js.form-data"]
    assert records[0]["severity"] == "informational"


def test_passive_receiver_transition_requires_identical_document_and_visible_target():
    overlay = row(hidden=True, intercepts=["#original"], receives_pointer=True, visual_mismatch=True,
                  classification="suspicious_interception")
    delta = {**DOC, "type": "receiver_changed", "after_receiver": "#r1", "before_receiver": "#original",
             "x": 21, "y": 12}
    checkpoints = {"early_ms": 81, "late_ms": 405, "early_screenshot": "initial",
                   "late_screenshot": "viewport", "changes": [delta]}
    result = report(regions=[overlay], passive_changes=checkpoints)
    chain = result["attack_sequences"][0]
    assert chain["attribution"] == "passive_observation" and chain["action_id"] is None
    assert chain["stages"][0]["evidence_ids"] == ["passive-1", "r1"]
    assert [s["elapsed_ms"] for s in chain["stages"]] == [81, 405]
    for change in [dict(delta, document_id="other"), dict(delta, before_receiver="#other")]:
        assert not report(regions=[overlay], passive_changes=dict(checkpoints, changes=[change]))["attack_sequences"]


@pytest.mark.parametrize("variation", ["paired", "other_form", "reversed", "other_doc", "other_url", "unknown_before"])
def test_scoped_form_destination_history_requires_order_identity_and_endpoint(variation):
    rows = [row(form="#entry"), row("entry", tag="form", credential=True, destination=PAGE)]
    common = {**REPLAY, "element_id": "r1", "action_id": "a1", "trigger_phase": "click",
              "provenance": "instrumentation", "url": DEST}
    change = {**common, "type": "form_destination_change", "from_url": PAGE, "form_selector": "#entry",
              "document_sequence": 3, "observation_index": 54}
    submission = {**common, "type": "form_submission", "credential": True, "blocked": True, "selector": "#entry",
                  "document_sequence": 4, "observation_index": 55}
    if variation == "other_form":
        change["form_selector"] = "#other"
    elif variation == "reversed":
        change["document_sequence"] = 6
    elif variation == "other_doc":
        change["document_id"] += "b"
    elif variation == "other_url":
        change["url"] += "/other"
    elif variation == "unknown_before":
        change["from_url"] = ""
    out = report(regions=rows, behavior=[change, submission])
    finding = next(f for f in out["findings"] if f["rule_id"] == "credentials.external-attempt")
    stages = out["attack_sequences"][0]["stages"]
    assert any(s["stage"] == "form_destination_change" for s in stages) == (variation == "paired")
    assert ("event-1" in finding["evidence_ids"]) == (variation == "paired")
    assert finding["evidence_status"] == "blocked_attempt" and finding["malicious_intent"] == "undetermined"


def test_sequence_preserves_scoped_secondary_effects_without_compounding_risk():
    common = {**REPLAY, "action_id": "a1", "element_id": "r1", "trigger_phase": "click"}
    transfer = {**common, "type": "request", "provenance": "playwright", "resource_type": "fetch",
                "blocked": True, "synthetic_credential": True, "url": DEST, "observation_index": 10}
    navigation = {**common, "type": "redirect", "provenance": "cdp", "url": DEST, "observation_index": 11}
    changed = {**common, "type": "visual_change", "provenance": "scanner", "observation_index": 12}
    other = {**common, "type": "download", "provenance": "playwright", "url": DEST,
             "frame_key": "main/frame-2", "document_id": "a1:main/frame-2@1", "observation_index": 13}
    out = report(behavior=[navigation, changed, other], network=[transfer])
    chain = out["attack_sequences"][0]
    assert [s["stage"] for s in chain["stages"]] == ["receiver", "request", "redirect", "visual_change"]
    assert out["scores"]["interaction_risk"] == 88 and len(out["findings"]) == 1


def test_page_level_form_attempts_preserve_distinct_destinations_and_source_evidence():
    base = {**DOC, "type": "form_submission", "frame_url": PAGE, "trigger_phase": "baseline",
            "selector": "#entry", "element_id": "r1", "action_id": None, "credential": True,
            "blocked": True, "provenance": "instrumentation", "resource_type": "fetch"}
    # Duplicate notifications for the same endpoint should stay in the evidence for that finding.
    other = "https://other.invalid/blocked"
    forms = [dict(base, url=dest) for dest in (DEST, DEST, other)]
    orphaned = dict(base, action_id="missing", url=DEST, trigger_phase="click")
    out = report(behavior=[*forms, orphaned])
    findings = out["findings"]
    assert len(findings) == 3
    assert [(s["attribution"], s["action_id"]) for s in out["attack_sequences"]] == [
        ("passive_observation", None), ("passive_observation", None), ("unknown_window", None)]
    assert [(f["destination"], f["evidence_ids"]) for f in findings] == [
        (DEST, ["event-1", "event-2"]), (other, ["event-3"]), (DEST, ["event-4"])]
    assert all(f["element_id"] is None and f["evidence_status"] == "blocked_attempt" for f in findings)
    assert all(e["attempted_element_id"] == "r1" and e["element_id"] is None for e in out["behavior"])
    assert out["behavior"][-1]["reported_action_id"] == "missing" and out["behavior"][-1]["action_id"] is None
    assert out["regions"][0]["risk_score"] == 0 and out["scores"]["javascript_risk"] == 0


def test_trusted_cdp_click_is_retained_with_independent_hook_corroboration():
    window = {**REPLAY, "element_id": "r1", "action_id": "a1", "trigger_phase": "click"}
    click = {**window, "type": "click", "trusted": True, "provenance": "cdp",
             "document_sequence": 4, "observation_index": 5, "corroborated_by": "instrumentation"}
    submit = {**window, "type": "form_submission", "provenance": "instrumentation", "credential": True,
              "blocked": True, "url": DEST, "frame_url": PAGE, "observation_index": 7}
    stages = report(behavior=[click, submit])["attack_sequences"][0]["stages"]
    observed = next(s for s in stages if s["stage"] == "click")
    assert observed["provenance"] == ["cdp", "instrumentation"] and observed["document_sequence"] == 4
