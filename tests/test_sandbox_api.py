import base64
import hashlib
import io
import os
import sqlite3
import subprocess
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from src.api.main import create_app
from src.sandbox.store import EvidenceStore


URL = "https://capture.example/"
HEADERS = {"Authorization": "Bearer unit-test-token"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path, token="unit-test-token", dispatch=False)) as session:
        yield session


def create(client, mode="analyze"):
    return client.post("/api/sandbox/" + mode, headers=HEADERS, json={"url": URL})


def test_auth_and_validation_precede_submission(client):
    assert client.post("/api/sandbox/analyze", json={"url": URL}).status_code == 401
    assert client.get("/api/sandbox/report/x").status_code == 401
    for url in ("file:///tmp/page", "http://127.0.0.1/", "https://user:pass@capture.example"):
        assert client.post("/api/sandbox/analyze", headers=HEADERS, json={"url": url}).status_code == 422
    assert client.post("/api/sandbox/analyze", headers=HEADERS, content="x"*9000).status_code == 413
    assert client.post("/api/sandbox/analyze", headers=HEADERS,
                       json={"url": URL, "allow_private": True}).status_code == 422


def test_pending_and_artifact_access(client):
    queued = create(client, "interaction-scan")
    assert queued.status_code == 202
    link = queued.headers["Location"]
    job = queued.json()["analysis_id"]
    assert client.get(link, headers=HEADERS).json()["status"] == "queued"
    assert client.get("/api/sandbox/interaction-map/" + job, headers=HEADERS).status_code == 409
    store = client.app.state.store
    assert store.claim() == job
    png = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(png, "PNG")
    store.complete(job, {"regions": [{"id": "r1"}], "viewport": {"width": 16, "height": 16},
                         "interactions": [], "behavior": [], "network": [{"blocked": True}],
                         "screenshots": {"viewport": base64.b64encode(png.getvalue()).decode()}})
    response = client.get(link, headers=HEADERS)
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["status"] == "completed"
    screenshot = response.json()["report"]["screenshots"]["viewport"]
    assert client.get(screenshot).status_code == 401
    assert client.get(screenshot, headers=HEADERS).content == png.getvalue()
    assert client.get(screenshot.replace("viewport", "unknown"), headers=HEADERS).status_code == 404
    assert client.get("/api/sandbox/interaction-map/" + job, headers=HEADERS).json()["regions"][0]["id"] == "r1"
    assert client.get("/api/sandbox/behavior-trace/" + job, headers=HEADERS).json() == []
    assert client.get("/api/sandbox/network-trace/" + job, headers=HEADERS).json() == [{"blocked": True}]
    store.fail(job, "failed", "stale completion")
    assert store.status(job)["status"] == "completed"


def test_prefixed_service_enforces_auth_and_body_budget(tmp_path):
    app = create_app(tmp_path, token="unit-test-token", dispatch=False)
    with TestClient(app, root_path="/lab") as session:
        endpoint = "/lab/api/sandbox/analyze"
        assert session.post(endpoint, json={"url": URL}).status_code == 401
        assert session.post(endpoint, headers=HEADERS, content="x"*9000).status_code == 413
        assert session.post(endpoint, headers=HEADERS, json={"url": URL}).status_code == 202


def test_bounded_queue_and_atomic_claim(client):
    for i in range(EvidenceStore.rate_limit):
        assert create(client, "javascript-analysis").status_code == 202
    assert create(client).status_code == 429
    with ThreadPoolExecutor(max_workers=5) as pool:
        claimed = list(pool.map(lambda _: client.app.state.store.claim(), range(5)))
    unique = [job for job in claimed if job]
    assert len(set(unique)) == len(unique) == EvidenceStore.concurrent_limit


def test_expiry_crash_recovery_and_atomic_image_storage(tmp_path):
    store = EvidenceStore(tmp_path)
    job = store.enqueue(URL, "analyze")
    assert store.claim() == job
    with pytest.raises(ValueError):
        store.complete(job, {"screenshots": {"viewport": "invalid"}})
    assert store.report(job) is None
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE jobs SET started=0")
    assert store.claim() is None
    assert store.status(job)["status"] == "timed_out"
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE jobs SET finished=0")
    store.claim()
    assert store.status(job) is None


def test_query_is_available_only_to_active_worker(client):
    url = URL + "?sample=sensitive-example"
    job = client.post("/api/sandbox/analyze", headers=HEADERS, json={"url": url}).json()["analysis_id"]
    store = client.app.state.store
    assert store.claim() == job
    assert store.input_url(job) == url
    assert store.status(job)["url"] == URL
    store.fail(job, "failed", "Fixture error.")
    assert store.input_url(job) is None


def test_identical_artifacts_share_storage_and_preserve_names_and_budgets(tmp_path):
    store = EvidenceStore(tmp_path)
    job = store.enqueue(URL, "analyze")
    assert store.claim() == job
    stream = io.BytesIO()
    Image.new("RGB", (8, 8), "navy").save(stream, "PNG")
    image = stream.getvalue()
    pos = image.index(b"IDAT")
    length = int.from_bytes(image[pos-4:pos], "big")
    broken = b"IDAT" + b"x" * length
    bad_pixels = image[:pos] + broken + zlib.crc32(broken).to_bytes(4, "big") + image[pos+8+length:]
    animated = io.BytesIO()
    Image.new("RGB", (8, 8), "navy").save(animated, "PNG", save_all=True,
        append_images=[Image.new("RGB", (8, 8), "white")])
    for bad in (image[:33], image[:-1], image + b"trailing bytes", image + image[-12:],
                bad_pixels, animated.getvalue()):
        with pytest.raises(ValueError, match="screenshot"):
            store.complete(job, {"screenshots": {"viewport": base64.b64encode(bad).decode()}})
    record = {"screenshots": dict.fromkeys(["viewport", "before", "after"], base64.b64encode(image).decode())}
    store.max_image_bytes = len(image)*2
    with pytest.raises(ValueError, match="budget"):
        store.complete(job, record)
    store.max_image_bytes = len(image)*3
    store.complete(job, record)
    assert all(store.image(job, name) == image for name in record["screenshots"])
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM images").fetchone()[0] == 1
        db.execute("DELETE FROM jobs WHERE id=?", (job,))
        assert db.execute("SELECT count(*) FROM image_aliases").fetchone()[0] == 0


def test_replay_retains_private_bytes_and_uses_no_live_capture(client):
    from src.sandbox import isolation, jobs
    from src.sandbox.isolation import encode_replay_bundle

    store = client.app.state.store
    source = create(client).json()["analysis_id"]
    endpoint = "/api/sandbox/replay/" + source
    assert client.post(endpoint, headers=HEADERS).status_code == 409
    bundle = {"url": URL, "mode": "analyze", "resources": {
        URL: {"status": 200, "headers": {"content-type": "text/html"}, "body": "cHJpdmF0ZQ=="}
    }}
    encoded = encode_replay_bundle(bundle)
    meta = {"image_id": "sha256:" + "a" * 64, "bundle_sha256": hashlib.sha256(encoded).hexdigest()}
    raw = {"url": URL, "final_url": URL, "viewport": {"width": 1, "height": 1},
           "capture": meta, "screenshots": {}, "interactions": [], "coverage": {}}
    model = {"status": "unavailable", "probability": None}
    assert store.claim() == source
    with patch.object(isolation, "run_sandbox", return_value={**raw, "_replay_bundle": bundle}), \
            patch("src.sandbox.analysis_model.predict_url", return_value=model):
        jobs.execute(store.path.parent, source)
    supplied = store.report(source)
    assert supplied["replay_available"] and "cHJpdmF0ZQ==" not in str(supplied)
    assert supplied["performance"]["model_inference_ms"] >= 0
    assert client.post(endpoint).status_code == 401
    job = client.post(endpoint, headers=HEADERS).json()["analysis_id"]
    assert store.claim() == job
    with store.connection() as db:
        db.execute("DELETE FROM jobs WHERE id=?", (source,))
    with patch.object(isolation, "run_sandbox", side_effect=AssertionError("Unexpected live capture")), \
            patch.object(isolation, "replay_capture", return_value=dict(raw)) as worker:
        jobs.execute(store.path.parent, job)
    worker.assert_called_once_with(bundle, expected_image_id=meta["image_id"])
    report = store.report(job)
    assert report["capture"]["replayed_from"] == source and report["replay_available"]
    assert report["existing_model_prediction"] == model
    assert report["model_evidence"]["evidence_status"] == "unavailable"
    assert report["replay_comparison"] == {"status": "matched", "changed_sections": []}
    assert report["performance"]["model_inference_ms"] is None
    assert report["performance"]["model_reused"]
    tampered = client.post("/api/sandbox/replay/" + job, headers=HEADERS).json()["analysis_id"]
    assert store.claim() == tampered
    with store.connection() as db:
        db.execute("UPDATE snapshots SET bundle=? WHERE job=?", (b"{}", tampered))
    with patch.object(isolation, "replay_capture", side_effect=AssertionError("Integrity check missed")), \
            pytest.raises(ValueError, match="integrity"):
        jobs.execute(store.path.parent, tampered)
    assert store.status(tampered)["status"] == "failed"


def test_shutdown_requires_token(tmp_path):
    with pytest.raises(RuntimeError, match="PHISHGUARD_SANDBOX_TOKEN"):
        with TestClient(create_app(tmp_path, token="")):
            pass


def test_dispatcher_fails_closed_with_no_docker(tmp_path):
    # Local test only. An empty PATH forces the production runner to fail preflight before DNS.
    with patch.dict(os.environ, {"PATH": ""}):
        with TestClient(create_app(tmp_path, token="unit-test-token")) as session:
            submitted = create(session)
            link = submitted.headers["Location"]
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                record = session.get(link, headers=HEADERS).json()
                if record["status"] in {"failed", "completed", "timed_out"}:
                    break
                time.sleep(0.15)
            assert record["status"] == "failed"
            assert "docker" in record["error"].lower()


@pytest.mark.parametrize("cause,expected", [
    ("crash", "failed"), ("deadline", "timed_out"), ("shutdown", "failed"),
])
def test_supervisor_reaps_interrupted_job_and_discards_inputs(tmp_path, monkeypatch, cause, expected):
    from src.sandbox.jobs import JobDispatcher

    store = EvidenceStore(tmp_path)
    store.deadline = 0.3 if cause == "deadline" else 15
    job = store.enqueue(URL + "?fixture=private", "interaction-scan")
    dispatcher = JobDispatcher(store)
    spawned = threading.Event()
    children = []
    launch = subprocess.Popen

    def controlled_child(command, **kwargs):
        assert command[1:3] == ["-m", "src.sandbox.jobs"]
        code = "raise SystemExit(5)" if cause == "crash" else "import time; time.sleep(30)"
        children.append(launch([sys.executable, "-c", code], **kwargs))
        spawned.set()
        return children[-1]

    monkeypatch.setattr(subprocess, "Popen", controlled_child)
    dispatcher.start()
    try:
        assert spawned.wait(8)
        if cause != "shutdown":
            deadline = time.monotonic()+8
            while store.status(job)["status"] == "running" and time.monotonic() < deadline:
                time.sleep(0.02)
    finally:
        dispatcher.stop()
    assert len(children) == 1 and children[0].poll() is not None
    assert store.status(job)["status"] == expected
    assert store.input_url(job) is None and store.report(job) is None
