"""Versioned fingerprint of the behavior actually observed during an offline session."""
from collections import Counter
import hashlib
import json
from urllib.parse import urlsplit


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _host(url: object) -> str:
    if not isinstance(url, str):
        return ""
    try:
        parts = urlsplit(url)
        if parts.scheme in {"http", "https", "ws", "wss"}:
            return (parts.hostname or "").rstrip(".").lower()
    except (ValueError, TypeError):
        pass
    return ""


def behavior_profile(report: dict) -> dict:
    """Sort and aggregate structural observations independently of capture IDs or clock time."""
    counts = {name: Counter() for name in ("dom", "javascript", "network", "navigation", "visual")}
    for row in report.get("regions", []):
        tag = row.get("tag")
        tag_str = tag if isinstance(tag, str) else ""
        input_type = row.get("input_type")
        input_type_str = input_type if isinstance(input_type, str) else ""
        role = row.get("role")
        role_str = role if isinstance(role, str) else ""
        frame_key = row.get("frame_key")
        frame_key_str = frame_key if isinstance(frame_key, str) else ""
        shadow_path = row.get("shadow_path")
        shadow_len = len(shadow_path) if isinstance(shadow_path, list) else 0
        dest = row.get("destination")
        dest_str = dest if isinstance(dest, str) else ""

        counts["dom"][(
            "region", tag_str, input_type_str, role_str,
            frame_key_str.count("/"), shadow_len,
            bool(row.get("interactive")), bool(row.get("credential")), bool(row.get("hidden")),
            bool(row.get("offscreen")), bool(row.get("intercepts")), _host(dest_str),
        )] += 1
    for change in report.get("passive_changes", {}).get("changes", []):
        counts["dom"][("checkpoint", str(change.get("type", "")))] += 1
    for rule in report.get("javascript_findings", []):
        counts["javascript"][("static", str(rule.get("rule_id", "")))] += 1
    for event in report.get("behavior", []):
        kind = str(event.get("type", ""))
        phase = str(event.get("trigger_phase", ""))
        if kind in {"redirect", "frame_navigation", "popup", "popup_attempt"}:
            u = event.get("url", "")
            counts["navigation"][(kind, _host(u if isinstance(u, str) else ""))] += 1
        if kind in {"form_submission", "credential_access", "clipboard_read", "clipboard_write",
                    "listener_registration", "iframe_inserted", "script_inserted",
                    "geolocation_request", "media_permission_request", "notification_permission_request",
                    "form_destination_change"}:
            # Presence of an operation in a phase survives repeated instrumentation notifications.
            counts["javascript"][("runtime", kind, phase)] = 1
    for event in report.get("network", []):
        # Live acquisition is absent during retained replay. Both sessions observe browser traffic.
        if event.get("provenance") == "broker":
            continue
        u = event.get("url", "")
        host = _host(u if isinstance(u, str) else "")
        counts["network"][(str(event.get("method", "")), host, str(event.get("resource_type", "")),
                           bool(event.get("blocked")), bool(event.get("synthetic_credential")))] += 1
        if event.get("navigation"):
            counts["navigation"][("document request", host)] += 1
    vision = report.get("vision", {})
    for line in vision.get("ocr_lines", []):
        for keyword in set(line.get("keywords", [])):
            counts["visual"][("control text", str(keyword))] += 1
    for logo in vision.get("brands", []):
        counts["visual"][("brand", str(logo.get("brand", "")), bool(logo.get("domain_mismatch")))] += 1
    for row in report.get("regions", []):
        if row.get("visual_mismatch"):
            tag = row.get("tag")
            counts["visual"][("pixel mismatch", tag if isinstance(tag, str) else "")] += 1
    for component, state in vision.get("backends", {}).items():
        # Runtime exception text is immaterial. Missing coverage must change the signature.
        counts["visual"][("backend", str(component), str(state).split(" (", 1)[0])] = 1
    for change in vision.get("changes", []):
        if change.get("bbox"):
            counts["visual"][("viewport changed",)] += 1

    sections = {}
    for name, events in counts.items():
        signature = sorted((list(key), count) for key, count in events.items())
        sections[name] = {"digest": _digest(signature), "observations": sum(events.values())}
    version = 1
    return {"version": version, "algorithm": "SHA-256",
            "digest": _digest([version, sections]), "sections": sections}


def compare_profiles(current: dict, source: dict | None) -> dict:
    if not source or source.get("version") != current.get("version"):
        return {"status": "unavailable", "changed_sections": []}
    if not current.get("sections") or current["sections"].keys() != source.get("sections", {}).keys():
        return {"status": "unavailable", "changed_sections": []}
    changed = [name for name, section in current["sections"].items()
               if section["digest"] != source["sections"][name]["digest"]]
    return {"status": "changed" if changed else "matched", "changed_sections": changed}
