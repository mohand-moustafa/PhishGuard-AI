from src.sandbox.analysis_profile import behavior_profile, compare_profiles


def test_behavior_fingerprint_ignores_run_ids_query_values_and_wire_capture():
    region = {"tag": "a", "interactive": True, "destination": "https://visible.invalid/go"}
    event = {"type": "request", "method": "GET", "navigation": True, "blocked": True,
             "resource_type": "document", "url": "https://dest.invalid/a?token=alpha"}
    observed = {"type": "credential_access", "trigger_phase": "click", "timestamp": "earlier"}
    source = behavior_profile({"regions": [region, {"tag": "form"}],
        "network": [event, {"provenance": "broker", "url": "https://capture.invalid/"}],
        "behavior": [observed], "vision": {"backends": {"ocr": "available"}}})
    replay = behavior_profile({"regions": [{"tag": "form"}, {**region, "id": "different"}],
        "behavior": [dict(observed, timestamp="later"), observed],
        "network": [dict(event, url="https://dest.invalid/b?token=beta", id="net-1")],
        "vision": {"backends": {"ocr": "available"}}})
    assert source == replay
    assert len(source["digest"]) == 64
    assert "alpha" not in str(source) and "beta" not in str(replay)


def test_profile_distinguishes_changed_destination_and_visual_backend_coverage():
    network = {"method": "POST", "url": "https://first.invalid/a", "blocked": True}
    before = behavior_profile({"network": [network], "vision": {"backends": {"ocr": "available"}}})
    after = behavior_profile({"network": [dict(network, url="https://second.invalid/a")],
                              "vision": {"backends": {"ocr": "unavailable"}}})
    result = compare_profiles(after, before)
    assert result == {"status": "changed", "changed_sections": ["network", "visual"]}
    for legacy in (None, {"version": 0}):
        assert compare_profiles(after, legacy)["status"] == "unavailable"


def test_document_and_shadow_structure_and_passive_transitions_enter_profile():
    control = {"tag": "button", "frame_key": "main/frame-1", "shadow_path": ["#component"]}
    original = behavior_profile({"regions": [control]})
    renamed = behavior_profile({"regions": [dict(control, frame_key="main/frame-9", shadow_path=["#other"])]})
    assert original == renamed
    changes = {"changes": [{"type": "receiver_changed"}]}
    for observed in ({"regions": [dict(control, frame_key="main")]},
                     {"regions": [dict(control, shadow_path=[])]},
                     {"regions": [control], "passive_changes": changes}):
        assert compare_profiles(behavior_profile(observed), original)["changed_sections"] == ["dom"]


def test_behavior_profile_handles_unhashable_region_fields():
    clobbered_region = {
        "tag": "form",
        "input_type": {"nested": "dict"},
        "role": ["unexpected", "list"],
        "destination": {"dict": "action"},
        "frame_key": None,
        "shadow_path": None,
        "interactive": True,
    }
    profile = behavior_profile({"regions": [clobbered_region]})
    assert profile["version"] == 1
    assert len(profile["digest"]) == 64

