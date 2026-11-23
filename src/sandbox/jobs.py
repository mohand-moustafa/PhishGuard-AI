"""Run a scan in its own supervisor process, with a deadline covering reporting too."""

import json
import hashlib
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path

from .store import EvidenceStore

logger = logging.getLogger("uvicorn.error")


def audit(event: str, job: str, **values):
    logger.info("%s", json.dumps({"event": event, "analysis_id": job, **values}))


def execute(directory: Path, job: str):
    from .analysis import build_report
    from .analysis_model import predict_url
    from .analysis_profile import compare_profiles
    from .isolation import encode_replay_bundle, replay_capture, run_sandbox, SandboxError, SandboxTimeout

    store = EvidenceStore(directory)
    record = store.status(job)
    if not record or record["status"] != "running":
        return
    started = time.perf_counter()
    cpu_started = time.process_time()
    try:
        url = store.input_url(job)
        snapshot = None
        source_profile = None
        model_ms = None
        if url is not None:
            stage = time.perf_counter()
            prediction = predict_url(url)
            model_ms = round((time.perf_counter() - stage) * 1000, 2)
            raw = run_sandbox(url, record["mode"])
            snapshot = encode_replay_bundle(raw.pop("_replay_bundle"))
        else:
            encoded, meta, source = store.replay_input(job)
            capture = meta["capture"]
            if hashlib.sha256(encoded).hexdigest() != capture["bundle_sha256"]:
                raise ValueError("Capture integrity check failed")
            raw = replay_capture(json.loads(encoded), expected_image_id=capture["image_id"])
            raw["capture"] = {**capture, **raw["capture"], "replayed_from": source}
            raw["url"] = record["url"]
            prediction = meta["model"]
            source_profile = meta.get("behavior_profile")
        raw["mode"] = record["mode"]
        report = build_report(raw, model_prediction=prediction)
        if url is None:
            report["replay_comparison"] = compare_profiles(report["behavior_profile"], source_profile)
        report.setdefault("performance", {}).update(
            model_inference_ms=model_ms,
            model_reused=url is None,
            processing_ms=round((time.perf_counter() - started) * 1000, 2),
            host_analysis_cpu_ms=round((time.process_time() - cpu_started) * 1000, 2),
            queue_ms=round(max(0, record["started"] - record["created"]) * 1000, 2),
        )
        store.complete(job, report, snapshot=snapshot)
    except SandboxTimeout:
        store.fail(job, "timed_out", "The capture or browser exceeded its execution deadline.")
    except SandboxError as exc:
        # Isolation exceptions can include untrusted addresses. Keep process diagnostics private.
        store.fail(job, "failed", exc.public_message)
    except Exception:
        store.fail(job, "failed", "Evidence processing failed.")
        raise


class JobDispatcher:
    def __init__(self, store: EvidenceStore):
        self.store = store
        self.stopping = threading.Event()
        self.wake = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="sandbox-dispatcher", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.wake.set()
        self.thread.join()

    def _run(self, job: str):
        audit("sandbox.started", job)
        try:
            with subprocess.Popen(
                [sys.executable, "-m", "src.sandbox.jobs", str(self.store.path.parent), job],
                cwd=Path(__file__).resolve().parents[2], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ) as scan:
                deadline = time.monotonic() + self.store.deadline
                while scan.poll() is None:
                    if self.stopping.wait(0.25) or time.monotonic() >= deadline:
                        scan.kill()
                        scan.wait()
                        if self.stopping.is_set():
                            self.store.fail(job, "failed", "Analysis interrupted by service shutdown.")
                        else:
                            self.store.fail(job, "timed_out", "Analysis exceeded its execution deadline.")
                        break
            # Handles a crash before a terminal record was committed.
            self.store.fail(job, "failed", "The scan worker exited unexpectedly.")
        except Exception:
            self.store.fail(job, "failed", "The scan worker could not be started.")
            logger.exception("sandbox.supervisor_error analysis_id=%s", job)
        finally:
            status = self.store.status(job)
            audit("sandbox.finished", job, status=status["status"] if status else "expired")
            self.wake.set()

    def _loop(self):
        workers: list[threading.Thread] = []
        try:
            while not self.stopping.is_set():
                workers = [worker for worker in workers if worker.is_alive()]
                try:
                    if len(workers) < self.store.concurrent_limit:
                        job = self.store.claim()
                        if job:
                            worker = threading.Thread(target=self._run, args=(job,), daemon=True)
                            workers.append(worker)
                            worker.start()
                            continue
                except Exception:
                    logger.exception("sandbox.dispatch_error")
                self.wake.wait(2)
                self.wake.clear()
        finally:
            for worker in workers:
                worker.join()


if __name__ == "__main__":
    execute(Path(sys.argv[1]), sys.argv[2])
