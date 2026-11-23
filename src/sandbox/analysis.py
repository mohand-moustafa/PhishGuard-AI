"""Explainable sandbox reports. Evidence is joined by action/region, never by time alone."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
import os
from pathlib import Path
import re
from time import perf_counter
from urllib.parse import urljoin, urlsplit

from .analysis_js import JavaScriptStaticAnalyzer, same_document
from .analysis_model import predict_url
from .analysis_vision import PhishGuardVisionAnalyzer


def _domain(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _external(destination: str | None, page: str | None) -> bool:
    return bool(_domain(destination) and _domain(page) and _domain(destination) != _domain(page))


@lru_cache(maxsize=1)
def _local_psl():
    import tldextract
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def _same_site(first: str, second: str) -> bool:
    a, b = _domain(first), _domain(second)
    try:
        extract = _local_psl()
        pair = [extract(host).top_domain_under_public_suffix for host in (a, b)]
        if all(pair):
            return pair[0] == pair[1]
    except ImportError:
        pass
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _severity(score: int) -> str:
    for minimum, name in ((85, "critical"), (65, "high"), (35, "medium"), (10, "low")):
        if score >= minimum:
            return name
    return "informational"


@lru_cache(maxsize=1)
def _flagged_domains(filename: str) -> frozenset[str]:
    with Path(filename).open("r", encoding="utf-8") as source:
        text = source.read(1024 * 1024 + 1)
    if len(text) > 1024 * 1024:
        raise ValueError("reputation list exceeds budget")
    return frozenset(s.strip().lower().rstrip(".") for s in text.splitlines()
                     if s.strip() and not s.lstrip().startswith("#"))


def _network(raw: dict) -> list[dict]:
    records = []
    for event in raw.get("broker_trace", []):
        item = dict(event, provenance="broker", type="capture", domain=event.get("destination_domain"))
        if isinstance(item.get("timestamp"), (float, int)):
            item["timestamp"] = datetime.fromtimestamp(item["timestamp"], timezone.utc).isoformat()
        if item.get("redirect"):
            item["redirect"] = urljoin(item["url"], item["redirect"])
        records.append(item)
    records.extend(raw.get("network", []))
    return [dict(event, id=f"net-{i}") for i, event in enumerate(records, 1)]


def _verified_window(action: dict, region: dict, event: dict) -> bool:
    return bool(action.get("receiver_verified") is True and action.get("status") == "tested"
                and region.get("document_id") and region["document_id"] == action.get("baseline_document_id")
                and region.get("frame_key") == action.get("frame_key")
                and same_document(action, event) and event.get("trigger_phase") == "click")


def _transfer(event: dict, origin: str) -> bool:
    return (event["type"] == "request" and event.get("provenance") == "playwright"
            and event.get("blocked") is True and event.get("synthetic_credential") is True
            and _external(event.get("url"), origin))


def _submission(event: dict, origin: str) -> bool:
    return (event["type"] == "form_submission" and event.get("provenance") == "instrumentation"
            and event.get("credential") is True and event.get("blocked") is True
            and _external(event.get("url"), origin))


def _prior_form_change(events: list[dict], submitted: dict) -> dict | None:
    """Both observations came from one document hook, in collector order, in a verified replay."""
    stop = submitted.get("observation_index")
    selector = submitted.get("selector")
    if not isinstance(stop, int) or not selector:
        return None
    candidates = [e for e in events if e["type"] == "form_destination_change" and e.get("form_selector") == selector
                  and same_document(e, submitted) and e.get("provenance") == "instrumentation"
                  and isinstance(e.get("observation_index"), int) and e["observation_index"] < stop]
    latest = max(candidates, key=lambda e: e["observation_index"], default={})
    if "document_sequence" in latest or "document_sequence" in submitted:
        old, new = latest.get("document_sequence"), submitted.get("document_sequence")
        if not (isinstance(old, int) and isinstance(new, int) and old < new):
            return None
    if latest.get("from_url") and latest.get("url") == submitted.get("url") and latest["from_url"] != latest["url"]:
        return latest
    return None


def _event_order(event: dict) -> tuple:
    # Network callbacks arrive immediately; instrumentation records can arrive in
    # batches from each document. The index guarantees observation order only.
    index = event.get("observation_index")
    return (0 if event.get("provenance") == "broker" else 1, index if isinstance(index, int) else 2**53,
            str(event.get("timestamp", "")))


def _stage(stage: str, label: str, ids: list[str], provenance: list[str], event: dict | None = None) -> dict:
    observation = event or {}
    return {"stage": stage, "label": label, "evidence_ids": ids, "provenance": provenance,
            "timestamp": observation.get("timestamp"), "observation_index": observation.get("observation_index"),
            "document_sequence": observation.get("document_sequence")}


def _sequence(finding: dict, action: dict, region: dict | None, context: list[dict],
              terminal: dict, events: list[dict], *, form_change: dict | None = None,
              password_selectors: set[str] | None = None, attribution: str = "verified_receiver") -> dict:
    stages = list(context)
    labels = {"click": "Trusted click on the verified receiver", "credential_access": "Password field read",
              "request": "External request with the synthetic marker blocked",
              "form_submission": "External password form submission blocked",
              "form_destination_change": "The submitted form's destination changed",
              "redirect": "Navigation requested", "popup_attempt": "Popup requested",
              "popup": "Popup observed", "download": "Download observed",
              "visual_change": "Viewport pixels changed during the probe",
              "receiver_change": "The receiver at the tested coordinate changed"}
    runtime = [terminal]
    if form_change:
        runtime.append(form_change)
    if region:
        # A read during the same action is context, never proof that its contents
        # reached a network request. Use the canary to establish that separately.
        for kind in ("click", "credential_access"):
            sources = {"cdp", "instrumentation"} if kind == "click" else {"instrumentation"}
            candidate = next((e for e in events if e["type"] == kind and e.get("provenance") in sources
                              and (kind != "click" or e.get("trusted") is True)
                              and (kind != "credential_access" or e.get("selector") in (password_selectors or set()))), None)
            if candidate:
                runtime.append(candidate)
        # A secondary side effect adds context without changing the episode's score.
        provenance = {"redirect": "cdp", "popup": "playwright", "download": "playwright",
                      "visual_change": "scanner", "receiver_change": "scanner"}
        for kind, source in provenance.items():
            if kind == terminal["type"]:
                continue
            candidate = next((e for e in events if e["type"] == kind and e.get("provenance") == source), None)
            if candidate:
                runtime.append(candidate)
    for event in sorted(runtime, key=_event_order):
        sources = [event["provenance"]]
        if event["type"] == "click" and sources == ["cdp"] and event.get("corroborated_by") == "instrumentation":
            sources.append("instrumentation")
        stage = _stage(event["type"], labels[event["type"]], [event["id"]], sources, event)
        if event is terminal and event.get("url"):
            stage["url"] = event["url"]
        if event["type"] == "form_destination_change":
            stage.update(from_url=event["from_url"], url=event["url"], form_selector=event["form_selector"],
                         coalesced=bool(event.get("coalesced")))
        if event["type"] == "visual_change" and action.get("after"):
            stage["screenshot"] = action["after"]
        stages.append(stage)
    unknown = ["Collector order can differ from script execution order."]
    if region:
        unknown.append("Other callbacks can run in the same document during the verified click window.")
    else:
        unknown.append("The observed destination cannot be attributed to a verified click receiver.")
    if terminal["type"] == "form_submission":
        unknown.append("The form hook observed a submission attempt and blocked the payload.")
    return {"id": f"sequence-{finding['id']}", "title": finding["title"], "finding_id": finding["id"],
            "action_id": action.get("id"), "element_id": region["id"] if region else None,
            "frame_key": terminal.get("frame_key"), "document_id": terminal.get("document_id"),
            "baseline_document_id": region.get("document_id") if region else None,
            "attribution": attribution, "severity": finding["severity"],
            "confidence": finding["confidence"], "evidence_status": finding["evidence_status"],
            "confidence_scope": "mechanism", "malicious_intent": "undetermined", "uncertainty": unknown, "stages": stages}


class InteractionThreatCorrelator:
    """Each observation family contributes at most its strongest finding to each score."""

    def correlate(self, raw: dict, javascript: list[dict], vision: dict, model: dict) -> dict:
        scores = dict(interaction_risk=0, javascript_risk=0, visual_deception=0, credential_theft_risk=0)
        findings = []
        regions = raw["regions"]
        page = raw.get("final_url") or raw["url"]
        actions = {a["id"]: a for a in raw.get("interactions", []) if a.get("id")}
        by_id = {r["id"]: r for r in regions}
        grouped = defaultdict(lambda: defaultdict(list))
        unassigned = defaultdict(list)
        sequences = []
        for event in raw["behavior"] + raw["network"]:
            action_id = event.get("action_id")
            action = actions.get(action_id)
            element_id = event.get("element_id")
            if (action and element_id and element_id == action.get("element_id")
                    and _verified_window(action, by_id.get(element_id, {}), event)):
                grouped[element_id][action_id].append(event)
            else:
                if element_id:
                    event["attempted_element_id"] = element_id
                    event["element_id"] = None
                if action_id and not action:
                    event["reported_action_id"] = action_id
                    event["action_id"] = None
                origin = event.get("frame_url") or page
                if _transfer(event, origin) or _submission(event, origin):
                    if action:
                        attribution = "action_only"
                    elif not action_id and event.get("trigger_phase") in {None, "baseline"}:
                        attribution = "passive_observation"
                    else:
                        attribution = "unknown_window"
                    key = (attribution, action_id, event.get("document_id"), event.get("selector"),
                           event["type"], event["url"])
                    unassigned[key].append(event)

        def add(rule, title, dimension, score, detail, refs, *, row=None, action_id=None, confidence=0.78):
            scores[dimension] = max(scores[dimension], score)
            if rule in {"credentials.synthetic-transfer", "credentials.external-attempt"}:
                status = "blocked_attempt"
            elif rule == "visual.brand-domain":
                status = "inferred"
            else:
                status = "observed"
            finding = {"id": f"finding-{len(findings)+1}", "rule_id": rule, "title": title,
                       "score": score, "severity": _severity(score), "confidence": confidence,
                       "evidence_status": status, "confidence_scope": "mechanism", "malicious_intent": "undetermined",
                       "element_id": row["id"] if row else None, "action_id": action_id,
                       "explanation": detail, "evidence_ids": list(dict.fromkeys(refs))[:28]}
            findings.append(finding)
            if row is not None:
                row["risk_score"] = max(row["risk_score"], score)
                row["finding_ids"].append(finding["id"])
            return finding

        for (attribution, action_id, _, _, _, url), attempts in unassigned.items():
            attempt = attempts[0]
            marker = attempt["type"] == "request"
            where = {"passive_observation": "during passive observation", "unknown_window": "outside a known action",
                     "action_only": "during the probe"}[attribution]
            result = add("credentials.synthetic-transfer" if marker else "credentials.external-attempt",
                "Synthetic password detected in a blocked external request" if marker else "External password form attempt",
                "credential_theft_risk", 88 if marker else 35,
                f"A blocked attempt targeted {_domain(url)} {where}. The click receiver is unverified.",
                [e["id"] for e in attempts], action_id=attempt.get("action_id"), confidence=0.97 if marker else 0.65)
            result["destination"] = url
            sequences.append(_sequence(result, actions.get(action_id, {}), None, [], attempt, [], attribution=attribution))
            if marker and attempt.get("resource_type") in {"xhr", "fetch"}:
                scores["javascript_risk"] = max(scores["javascript_risk"], 85)

        js_by_element = defaultdict(list)
        text_by_element = defaultdict(list)
        for i, line in enumerate(vision["ocr_lines"], 1):
            line["id"] = f"ocr-{i}"
            if line.get("keywords"):
                for element_id in line["element_ids"] + line.get("occluding_receiver_ids", []):
                    text_by_element[element_id].append(line["id"])
        for signal in javascript:
            js_by_element[signal.get("element_id")].append(signal)
            static_score = {"medium": 36, "low": 12}.get(signal["severity"], 0)
            scores["javascript_risk"] = max(scores["javascript_risk"], static_score)

        for row in regions:
            row["risk_score"] = 0
            row["finding_ids"] = []
            row["confirmed_mechanism"] = None
            region_id = row["id"]
            category = row.get("classification", "")
            interception = category == "suspicious_interception" and bool(row.get("intercepts"))
            hidden_receiver = category == "invisible_receiver"
            linked_js = js_by_element[region_id]
            js_ids = [item["id"] for item in linked_js if item["severity"] != "informational"]
            credential_form = category == "hidden_credential_form"
            if row.get("tag") == "a" and not row.get("hidden"):
                label = str(row.get("visible_text", "")).strip()
                # Require an explicit web address as the whole label. Marketing copy
                # and ordinary login links are too ambiguous for this comparison.
                if re.fullmatch(r"(?:(?:https?://|www\.)[^\s]+|(?:[\w-]+\.)+[a-z]{2,63}/?)", label, re.I):
                    shown = label if "://" in label else "https://" + label
                    if _external(row.get("destination"), shown):
                        same_site = _same_site(row["destination"], shown)
                        pixels = [line["id"] for line in vision["ocr_lines"]
                                  if region_id in line["element_ids"]
                                  and label.casefold() == line["text"].strip().casefold()]
                        add("visual.link-destination", "Displayed address differs from the link destination",
                            "visual_deception", 8 if same_site else 44,
                            ("The link names another host on the same site." if same_site else
                             "The visible link label and href identify different sites."),
                            [region_id, *pixels], row=row, confidence=0.9 if pixels else 0.78)
            if interception or hidden_receiver:
                score = 65 if interception else 35
                if interception and row.get("visual_mismatch"):
                    score = 73
                    scores["visual_deception"] = max(scores["visual_deception"], 70)
                elif interception:
                    scores["visual_deception"] = max(scores["visual_deception"], 48)
                detection = add("interaction.intercepts" if interception else "interaction.hidden-receiver",
                    "Hidden layer intercepts a visible control" if interception else "Invisible pointer receiver",
                    "interaction_risk", score, row.get("explanation", ""),
                    [region_id, *text_by_element[region_id], *js_ids], row=row,
                    confidence=row.get("confidence", 0.7))
                passive = raw.get("passive_changes", {})
                transition = next((change for change in passive.get("changes", []) if
                    same_document(change, row) and change.get("type") == "receiver_changed"
                    and change.get("after_receiver") == row.get("selector")
                    and change.get("before_receiver") in row.get("intercepts", [])), None)
                if transition:
                    stages = []
                    for checkpoint, receiver in (("early", transition["before_receiver"]),
                                                 ("late", transition["after_receiver"])):
                        stage = _stage(checkpoint + "_receiver", "Sampled pointer receiver " + receiver,
                                       [transition["id"], region_id], ["dom", "hit_test"])
                        stage.update(elapsed_ms=passive.get(checkpoint + "_ms"),
                                     screenshot=passive.get(checkpoint + "_screenshot"))
                        stages.append(stage)
                    sequences.append({"id": "sequence-" + detection["id"], "title": "Pointer receiver changed between samples",
                        "finding_id": detection["id"], "action_id": None, "element_id": region_id,
                        "frame_key": row["frame_key"], "document_id": row["document_id"],
                        "baseline_document_id": row["document_id"], "attribution": "passive_observation",
                        "severity": detection["severity"], "confidence": detection["confidence"],
                        "evidence_status": "observed", "confidence_scope": "mechanism", "malicious_intent": "undetermined",
                        "uncertainty": ["The two checkpoints establish a receiver change. Its initiating script is unknown."],
                        "stages": stages})
            if credential_form:
                add("credentials.hidden-form", "Hidden credential form names another host", "credential_theft_risk",
                    43, "The DOM contains a hidden password form with an external destination.",
                    [region_id], row=row)
            for action_id, events in grouped[region_id].items():
                origin = row.get("frame_url") or page
                action = actions[action_id]
                side_effects = [e for e in events if
                    (e["type"] in {"popup", "download"} and e.get("provenance") == "playwright")
                    or (e["type"] == "popup_attempt" and e.get("provenance") == "instrumentation")
                    or (e["type"] == "redirect" and e.get("provenance") == "cdp" and _external(e.get("url"), origin))]
                submissions = [e for e in events if _submission(e, origin)]
                synthetic = [e for e in events if _transfer(e, origin)]
                if not (submissions or synthetic or (side_effects and (interception or hidden_receiver))):
                    continue
                targets = [r["id"] for r in regions if same_document(r, row)
                           and r.get("selector") in row.get("intercepts", [])][:4]
                stages = [_stage("receiver", "Sampled visible control and actual receiver" if interception
                                 else "Sampled receiver", [region_id, *targets], ["dom", "hit_test"])]
                if text_by_element[region_id]:
                    stages.append(_stage("visible_label", "Control text observed in viewport pixels",
                                         text_by_element[region_id][:4], ["ocr"]))
                if submissions or synthetic:
                    handler_rules = {"js.form-submit", "js.form-destination", "js.form-data", "js.credential-read"}
                else:
                    handler_rules = {"js.navigate", "js.popup"}
                matching = [s["id"] for s in linked_js if s["rule_id"] in handler_rules]
                if matching:
                    stages.append(_stage("handler", "Associated source contains a compatible operation",
                                         matching[:4], ["static_ast"]))
                change = None
                credential_form_selector = row.get("form")
                if synthetic:
                    attempt = synthetic[0]
                    terminal = attempt
                    score = 97 if interception and row.get("visual_mismatch") else 88
                    row["confirmed_mechanism"] = (
                        "deceptive_receiver_attempted_external_credential_transfer"
                        if interception and row.get("visual_mismatch") else "attempted_external_synthetic_credential_transfer"
                    )
                    refs = [region_id, attempt["id"], *text_by_element[region_id], *matching]
                    result = add("credentials.synthetic-transfer", "Synthetic password detected in a blocked external request",
                        "credential_theft_risk", score,
                        "The browser intercepted an outbound request containing the synthetic marker entered for this action.",
                        refs, row=row, action_id=action_id, confidence=0.98)
                    scores["interaction_risk"] = max(scores["interaction_risk"], score)
                    if attempt.get("resource_type") in {"xhr", "fetch"}:
                        scores["javascript_risk"] = max(scores["javascript_risk"], 85)
                elif submissions:
                    form = submissions[0]
                    terminal = form
                    mutation = _prior_form_change(events, form)
                    # Use the submitted form's own observed password fields/destination.
                    # An unrelated analytics POST alongside a password read does not qualify.
                    candidates = [candidate for candidate in regions if candidate.get("tag") == "form"
                        and candidate.get("credential") and candidate.get("selector") == form.get("selector")
                        and (candidate.get("destination") == form.get("url") or
                             (mutation and candidate.get("destination") == mutation["from_url"]))
                        and same_document(row, candidate)]
                    confirmed_form = candidates[0] if len(candidates) == 1 else None
                    if confirmed_form:
                        credential_form_selector = confirmed_form["selector"]
                        change = mutation
                    related_handler = any(s["rule_id"] == "js.form-submit" for s in linked_js)
                    strong = bool(interception and row.get("visual_mismatch") and confirmed_form
                                  and (related_handler or row.get("form") == form.get("selector")))
                    if strong:
                        row["confirmed_mechanism"] = "deceptive_receiver_with_blocked_external_password_form"
                    score = 94 if strong else 79 if interception else 52
                    refs = [region_id, form["id"], *text_by_element[region_id], *matching]
                    if change:
                        refs.append(change["id"])
                    if confirmed_form:
                        refs.append(confirmed_form["id"])
                    wording = "The action reached a password form targeting a different host."
                    if interception:
                        wording += " Hit testing placed an invisible receiver over the visible control."
                    if form.get("blocked"):
                        wording += " The sandbox blocked submission."
                    if strong:
                        wording += " The captured DOM identifies the form and the observed destination history."
                    result = add("credentials.external-attempt", "External credential submission attempt", "credential_theft_risk",
                        score, wording, refs, row=row, action_id=action_id, confidence=0.96 if strong else 0.79)
                    if interception:
                        scores["interaction_risk"] = max(scores["interaction_risk"], score)
                    if matching:
                        scores["javascript_risk"] = max(scores["javascript_risk"], 60)
                elif side_effects and (interception or hidden_receiver):
                    side = side_effects[0]
                    terminal = side
                    result = add("interaction.hidden-side-effect", "Unexpected effect after hitting a hidden receiver",
                        "interaction_risk", 78 if interception else 61,
                        f"The offline action was followed by a {side['type']} event.",
                        [region_id, side["id"], *matching], row=row, action_id=action_id)
                    if matching:
                        scores["javascript_risk"] = max(scores["javascript_risk"], 48)
                passwords = {r["selector"] for r in regions if credential_form_selector and same_document(row, r)
                             and r.get("input_type") == "password" and r.get("form") == credential_form_selector}
                sequences.append(_sequence(result, action, row, stages, terminal, events,
                                           form_change=change, password_selectors=passwords))

        for index, brand in enumerate(vision["brands"]):
            if not brand["domain_mismatch"]:
                continue
            candidates = [by_id[i] for i in brand["element_ids"] if i in by_id]
            row = candidates[0] if candidates else None
            corroborated = (brand.get("clip_similarity") or 0) >= 0.85
            brand["id"] = f"brand-{index+1}"
            add("visual.brand-domain", "Logo candidate on an unregistered host", "visual_deception",
                50 if corroborated else 35,
                f"The logo resembles {brand['brand']}. The current host is outside its configured domain list.",
                [brand["id"]], row=row, confidence=0.81 if corroborated else 0.66)
        # Local exact-host verdicts only. Origin changes and blocked requests alone
        # do not imply poor reputation.
        reputation = "unconfigured"
        if filename := os.environ.get("PHISHGUARD_FLAGGED_DOMAINS"):
            try:
                flagged = _flagged_domains(filename)
                reputation = "available"
                seen = set()
                for event in raw["network"]:
                    host = event.get("domain")
                    if host not in flagged or host in seen:
                        continue
                    seen.add(host)
                    add("network.flagged-host", "Destination matches the configured reputation list",
                        "interaction_risk", 66, f"Destination host {host} has a local negative reputation entry.",
                        [event["id"]], row=by_id.get(event.get("element_id")))
            except (OSError, ValueError):
                reputation = "unavailable"
        model_risk = round(100 * model["probability"]) if model.get("probability") is not None else 0
        scores["overall_website_risk"] = max(model_risk, *scores.values())
        for row in regions:
            if row["finding_ids"]:
                row["severity"] = _severity(row["risk_score"])
        return {"scores": scores, "findings": findings, "attack_sequences": sequences, "reputation_status": reputation,
                "scoring": {"scale": "0-100", "method": "Maximum supported score per dimension",
                            "overall": "Maximum of the four evidence scores and the existing model probability × 100",
                            "probability_source": model.get("model") if model.get("probability") is not None else None}}


def _viewport_sampling(viewport: dict, regions: list[dict]) -> dict | None:
    """Count distinct final-checkpoint hit-test positions in viewport cells."""
    width, height = viewport.get("width", 0), viewport.get("height", 0)
    if width <= 0 or height <= 0:
        return None
    columns, rows = 8, 6
    cells = [[0] * columns for _ in range(rows)]
    seen = set()
    unsampled = 0
    for region in regions:
        points = {(p["x"], p["y"]) for p in region.get("points", [])
                  if 0 <= p["x"] < width and 0 <= p["y"] < height}
        unsampled += not points
        for x, y in points - seen:
            cells[int(y * rows / height)][int(x * columns / width)] += 1
        seen.update(points)
    return {"checkpoint": "viewport", "cells": cells, "distinct_positions": len(seen),
            "regions_without_viewport_samples": unsampled}


def build_report(raw: dict, *, model_prediction: dict | None = None) -> dict:
    """Convert one worker bundle into a JSON report and a separately storable screenshot set."""
    report = {k: raw[k] for k in ("url", "final_url", "viewport", "coverage", "capture", "interactions",
                                  "screenshots", "mode", "passive_changes") if k in raw}
    performance = dict(raw.get("performance") or {})
    sanitized_regions = []
    for r in raw.get("regions", []):
        r_copy = dict(r)
        for field in ("tag", "input_type", "role", "destination", "frame_key", "selector"):
            val = r_copy.get(field)
            if not isinstance(val, str):
                r_copy[field] = "" if val is None or isinstance(val, (dict, list)) else str(val)
        sanitized_regions.append(r_copy)
    report["regions"] = sanitized_regions
    raw["regions"] = sanitized_regions
    if "passive_changes" in report:
        passive = report["passive_changes"]
        report["passive_changes"] = {**passive, "changes": [dict(c, id=f"passive-{i}")
                                     for i, c in enumerate(passive.get("changes", [])[:64], 1)]}
    report["behavior"] = [dict(e, id=f"event-{i}") for i, e in enumerate(raw.get("behavior", []), 1)]
    report["network"] = _network(raw)
    sources = raw.get("scripts", [])
    start = perf_counter()
    javascript, static_coverage = JavaScriptStaticAnalyzer().analyze(sources, report["behavior"])
    for finding in javascript:
        scoped = [r for r in report["regions"] if same_document(r, finding)]
        matches = [r for r in scoped if finding.get("selector") and r.get("selector") == finding["selector"]]
        if len(matches) == 1:
            finding.update(element_id=matches[0]["id"], association="document_selector")
        elif finding.get("function_header") and finding.get("source"):
            start_position, end_position = finding["function_header"]
            matching = [r for r in scoped if any(h.get("source") == finding["source"]
                         and start_position <= [h.get("line", 0), h.get("column", 0)] <= end_position
                         for h in r.get("handler_locations", []))]
            if len(matching) == 1:
                finding.update(element_id=matching[0]["id"], association="cdp_listener_location")
    performance["javascript_ms"] = round((perf_counter() - start) * 1000, 3)
    for key in ("behavior", "network"):
        for e in report[key]:
            # Only verified action windows carry cause attribution. Page-load
            # activity can carry a selector or initiator without an action.
            e.setdefault("action_id", None)
            e.setdefault("element_id", None)
    start = perf_counter()
    vision = PhishGuardVisionAnalyzer().analyze(report)
    performance["vision_ms"] = round((perf_counter() - start) * 1000, 3)
    model = model_prediction if model_prediction is not None else predict_url(raw["url"])
    report["model_evidence"] = {
        "evidence_status": "model_prediction" if model.get("probability") is not None else "unavailable",
        "confidence_scope": "url_classification_probability",
    }
    start = perf_counter()
    report.update(InteractionThreatCorrelator().correlate(report, javascript, vision, model))
    performance["correlation_ms"] = round((perf_counter() - start) * 1000, 3)
    timeline = sorted(report["behavior"] + report["network"], key=_event_order)
    report.update(schema_version=1, vision=vision, javascript_findings=javascript,
                  existing_model_prediction=model, final_phishing_probability=model.get("probability"),
                  performance=performance,
                  evidence_timeline=[{k: e[k] for k in ("id", "type", "timestamp", "action_id", "element_id",
                      "provenance", "frame_key", "document_id", "observation_index", "document_sequence", "trigger_phase") if k in e}
                      for e in timeline])
    report.setdefault("coverage", {})
    report["coverage"] = {**report["coverage"], "static_analysis": static_coverage}
    grid = _viewport_sampling(raw.get("viewport", {}), report["regions"])
    if grid is not None:
        report["coverage"]["viewport_sampling"] = grid
    # Index findings/traces by ID rather than storing several copies of evidence.
    report["transparent_elements"] = [r["id"] for r in report["regions"] if r.get("hidden")]
    report["suspicious_overlays"] = [r["id"] for r in report["regions"]
                                     if r.get("classification") in {"suspicious_interception", "invisible_receiver"}]
    report["click_interceptions"] = [r["id"] for r in report["regions"] if r.get("intercepts")]
    report["redirect_findings"] = [e["id"] for e in timeline if e["type"] == "redirect" or e.get("redirect")]
    report["network_findings"] = [f["id"] for f in report["findings"]
                                  if f["rule_id"] in {"network.flagged-host", "credentials.external-attempt",
                                                      "credentials.synthetic-transfer"}]
    report["brand_impersonation_findings"] = [f["id"] for f in report["findings"]
                                               if f["rule_id"] == "visual.brand-domain"]
    forms = [r for r in report["regions"] if r.get("tag") == "form"]
    report["html_features"] = {
        "sampled_regions": len(report["regions"]), "sampled_forms": len(forms),
        "credential_forms": sum(bool(r.get("credential")) for r in forms),
        "hidden_forms": sum(bool(r.get("hidden")) for r in forms),
        "external_action_forms": sum(_external(r.get("destination"), r.get("frame_url")) for r in forms),
        "iframe_regions": sum(r.get("tag") == "iframe" for r in report["regions"]),
        "observed_script_sources": len(sources),
    }
    mitigations = []
    if report["suspicious_overlays"]:
        mitigations.append("Inspect the covering element, its handler, and the underlying control before allowing interaction.")
    if report["scores"]["credential_theft_risk"]:
        mitigations.append("Verify the form destination with the service owner before entering credentials.")
    if report["brand_impersonation_findings"]:
        mitigations.append("Verify the displayed brand and host against the organization's official domains.")
    if any(f["rule_id"] == "network.flagged-host" for f in report["findings"]):
        mitigations.append("Review the flagged destination and apply the organization's network blocking policy.")
    if model.get("label") == "phishing":
        mitigations.append("Review the URL model prediction and its PCA-component contributions before allowing access.")
    report["mitigations"] = mitigations
    from .analysis_profile import behavior_profile
    report["behavior_profile"] = behavior_profile(report)
    return report
