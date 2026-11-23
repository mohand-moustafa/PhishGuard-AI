"""Time the reviewed actions.html replay in local Chromium. Run from the repository root."""
import base64
import json
import os
from pathlib import Path
import runpy
import threading
import time
from unittest.mock import patch

import psutil
from playwright.sync_api import sync_playwright

from src.sandbox.analysis import build_report
from src.sandbox.analysis_model import predict_url
from src.sandbox.analysis_profile import compare_profiles
from src.sandbox.browser import SafeInteractionEngine
from src.sandbox import isolation_capture


def fixture_capture_ms(fixture):
    """Measure broker discovery/archiving with the two reviewed response bodies in memory."""
    resources = {url: isolation_capture.Captured(item["status"], item["headers"],
                 base64.b64decode(item["body"], validate=True), "fixture")
                 for url, item in fixture["resources"].items()}

    def read_fixture(url, limit, deadline, budget):
        response = resources[url]
        assert len(response.body) <= min(limit, budget.remaining)
        budget.remaining -= len(response.body)
        return response

    with patch.object(isolation_capture, "_get", read_fixture):
        started = time.perf_counter()
        output = isolation_capture.capture(fixture["url"])
        elapsed = (time.perf_counter() - started) * 1000
    assert output["resources"] == fixture["resources"]
    return round(elapsed, 3)


def sample_tree(stop, usage):
    """RSS is a sampled sum of working sets and may count shared pages twice."""
    parent = psutil.Process()
    while not stop.is_set():
        resident = 0
        for process in [parent, *parent.children(recursive=True)]:
            try:
                resident += process.memory_info().rss
                cpu = process.cpu_times()
                usage["cpu"][(process.pid, process.create_time())] = cpu.user + cpu.system
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        usage["peak_bytes"] = max(resident, usage["peak_bytes"])
        stop.wait(0.1)


def main():
    root = Path(__file__).resolve().parents[2]
    fixture = runpy.run_path(str(root / "tests/test_sandbox_browser.py"))["bundle"]("actions.html", "analyze")
    stop = threading.Event()
    usage = {"peak_bytes": 0, "cpu": {}}
    observer = threading.Thread(target=sample_tree, args=(stop, usage), daemon=True)
    runs = []
    source_profile = None
    parent = psutil.Process()
    initial_cpu = {}
    for process in [parent, *parent.children(recursive=True)]:
        try:
            cpu = process.cpu_times()
            initial_cpu[(process.pid, process.create_time())] = cpu.user + cpu.system
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    start = time.perf_counter()
    observer.start()
    try:
        with sync_playwright() as tools:
            stage = time.perf_counter()
            with tools.chromium.launch(executable_path=os.getenv("PHISHGUARD_FIXTURE_CHROMIUM"),
                    chromium_sandbox=True, args=["--disable-background-networking",
                    "--host-resolver-rules=MAP * ~NOTFOUND"]) as browser:
                startup = time.perf_counter() - stage
                for _ in range(3):
                    capture_ms = fixture_capture_ms(fixture)
                    stage = time.perf_counter()
                    model = predict_url(fixture["url"])
                    model_s = time.perf_counter() - stage
                    stage = time.perf_counter()
                    raw = SafeInteractionEngine(browser, fixture["url"], fixture["resources"]).analyze("analyze")
                    browser_s = time.perf_counter() - stage
                    stage = time.perf_counter()
                    report = build_report(raw, model_prediction=model)
                    profile = report["behavior_profile"]
                    runs.append({"model_s": round(model_s, 3), "browser_fixture_s": round(browser_s, 3),
                                 "report_s": round(time.perf_counter() - stage, 3),
                                 "regions": len(report["regions"]), "actions": len(report["interactions"]),
                                 "fixture_capture_without_transport_ms": capture_ms,
                                 "profile_comparison": compare_profiles(profile, source_profile) if source_profile else None,
                                 "performance": report.get("performance", {})})
                    source_profile = source_profile or profile
    finally:
        stop.set()
        observer.join()
    elapsed = time.perf_counter() - start
    cpu_seconds = sum(max(0, value - initial_cpu.get(pid, 0)) for pid, value in usage["cpu"].items())
    print(json.dumps({"fixture": "actions.html", "launch_s": round(startup, 3),
                      "elapsed_s": round(elapsed, 3),
                      "sampled_peak_tree_rss_mib": round(usage["peak_bytes"] / 2**20, 1),
                      "sampled_tree_cpu_s": round(cpu_seconds, 2),
                      "sampled_mean_cpu_cores": round(cpu_seconds / elapsed, 2), "runs": runs}, indent=2))


if __name__ == "__main__":
    main()
