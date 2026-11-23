"""Local-only orchestration of a bounded capture and a networkless disposable Chromium."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import REPLAY_HEADERS
from .isolation_capture import (BUNDLE_LIMIT, CAPTURE_TIMEOUT, MAX_ASSETS,
                                RESOURCE_LIMIT, SandboxError, SandboxTimeout, valid_header, validate_url)


RUN_TIMEOUT = 150
IMAGE = "phishguard-browser:local"
CAPTURE_OUTPUT = 28 * 1024 * 1024
WORKER_OUTPUT = 28 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]
SECCOMP = Path(__file__).with_name("isolation_seccomp.json")
MODES = {"analyze", "interaction-scan", "javascript-analysis"}
LOG = logging.getLogger(__name__)


def _exchange(command: list[str], payload: bytes, timeout: float, limit: int, label: str) -> dict:
    """Bound both directions, without spooling site-controlled bytes to disk or logs."""
    try:
        proc = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as error:
        raise SandboxError(f"{label} could not start") from error
    output = bytearray()
    err_output = bytearray()

    def send() -> None:
        try:
            with proc.stdin as pipe:
                pipe.write(payload)
        except (OSError, ValueError):
            pass

    def receive() -> None:
        with proc.stdout as pipe:
            while len(output) <= limit:
                chunk = pipe.read(min(64 * 1024, limit + 1 - len(output)))
                if not chunk:
                    return
                output.extend(chunk)
        proc.kill()

    def receive_err() -> None:
        with proc.stderr as pipe:
            while len(err_output) < 64 * 1024:
                chunk = pipe.read(min(4096, 64 * 1024 - len(err_output)))
                if not chunk:
                    return
                err_output.extend(chunk)

    writer = threading.Thread(target=send, daemon=True)
    reader = threading.Thread(target=receive, daemon=True)
    err_reader = threading.Thread(target=receive_err, daemon=True)
    writer.start()
    reader.start()
    err_reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        proc.kill()
        proc.wait(timeout=3)
        raise SandboxTimeout(f"{label} timed out") from error
    finally:
        reader.join(timeout=2)
        writer.join(timeout=2)
        err_reader.join(timeout=2)
    if len(output) > limit or reader.is_alive():
        raise SandboxError(f"{label} output exceeded its limit")
    if proc.returncode == 124:
        raise SandboxTimeout(f"{label} timed out")
    if proc.returncode == 78 and label == "Isolated browser":
        raise SandboxError("Worker rejected effective kernel isolation or resource limits")
    if proc.returncode != 0:
        err_text = err_output.decode("utf-8", errors="replace").strip()
        if err_text:
            LOG.error("%s stderr: %s", label, err_text)
            print(f"[{label} exit {proc.returncode} STDERR]: {err_text}", file=sys.stderr)
        raise SandboxError(f"{label} failed (exit {proc.returncode})")
    try:
        result = json.loads(output)
    except (ValueError, RecursionError) as error:
        raise SandboxError(f"{label} returned malformed output") from error
    if not isinstance(result, dict):
        raise SandboxError(f"{label} returned malformed output")
    return result


def _docker(config: str) -> list[str]:
    executable = shutil.which("docker")
    if not executable:
        raise SandboxError("Local Docker CLI is unavailable")
    if os.name == "nt":
        endpoint = "npipe:////./pipe/docker_engine"
    else:
        local_socket = os.getenv("PHISHGUARD_DOCKER_SOCKET", "/var/run/docker.sock")
        if not local_socket.startswith("/") or "\0" in local_socket:
            raise SandboxError("Local Docker socket path is invalid")
        endpoint = "unix://" + local_socket
    # A fresh config also avoids injecting client-side proxy credentials into containers.
    return [executable, "--host", endpoint, "--config", config]


def _run_args(docker: list[str], name: str, image_id: str = IMAGE) -> list[str]:
    runtime = os.getenv("PHISHGUARD_SANDBOX_RUNTIME", "")
    if runtime not in {"", "runc", "runsc"}:
        raise SandboxError("Unknown sandbox runtime")
    runtime_args = ["--runtime", runtime] if runtime else []
    return [
        *docker, "run", "--pull=never", "--rm", "-i", "--init", "--name", name,
        "--label", "phishguard.role=offline-scanner", *runtime_args,
        "--network=none", "--ipc=private", "--cgroupns=private", "--read-only",
        "--user", "65532:65532", "--cap-drop=ALL", "--security-opt", "no-new-privileges=true",
        "--security-opt", f"seccomp={SECCOMP}", "--cpus=1.0", "--memory=768m",
        "--memory-swap=768m", "--pids-limit=160", "--shm-size=128m", "--ulimit", "core=0:0",
        "--ulimit", "nofile=1024:1024", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=160m,mode=1777",
        "--log-driver=none", "--no-healthcheck", "--entrypoint", "/usr/bin/timeout",
        image_id, "--kill-after=2s", f"{RUN_TIMEOUT - 4}s", "python", "-m", "src.sandbox.worker",
    ]


def _preflight(docker: list[str]) -> str:
    try:
        check = subprocess.run([*docker, "image", "inspect", "--format", "{{.Id}}", IMAGE],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    except subprocess.TimeoutExpired as error:
        raise SandboxTimeout("Local Docker preflight timed out") from error
    except OSError as error:
        raise SandboxError("Local Docker is unavailable") from error
    if check.returncode != 0:
        raise SandboxError("Local Docker daemon or phishguard-browser:local image is unavailable")
    digest = check.stdout.strip()
    if not re.fullmatch(rb"sha256:[a-f0-9]{64}", digest):
        raise SandboxError("Invalid local Docker image identity")
    return digest.decode("ascii")


def encode_replay_bundle(bundle: dict) -> bytes:
    """Canonical bytes hashed, passed to the isolated worker and privately retained for replay."""
    if (not isinstance(bundle, dict) or set(bundle) != {"url", "mode", "resources"}
            or not isinstance(bundle["url"], str) or not isinstance(bundle["mode"], str)
            or bundle["mode"] not in MODES or not isinstance(bundle["resources"], dict)
            or not 1 <= len(bundle["resources"]) <= MAX_ASSETS + 1 or bundle["url"] not in bundle["resources"]):
        raise SandboxError("Invalid offline resource bundle")
    root = urlsplit(validate_url(bundle["url"]))
    total = 0
    for url, item in bundle["resources"].items():
        canonical = validate_url(url)
        parts = urlsplit(canonical)
        if (canonical != url or (parts.scheme, parts.netloc) != (root.scheme, root.netloc)
                or not isinstance(item, dict) or set(item) != {"body", "status", "headers"}
                or type(item["status"]) is not int or not 200 <= item["status"] < 300 or item["status"] == 206):
            raise SandboxError("Invalid offline resource bundle")
        headers = item["headers"]
        if not isinstance(headers, dict) or len(headers) > len(REPLAY_HEADERS):
            raise SandboxError("Invalid offline resource bundle")
        for key, value in headers.items():
            if key not in REPLAY_HEADERS or not valid_header(value):
                raise SandboxError("Invalid offline resource bundle")
        if url == bundle["url"] and headers.get("content-type", "").partition(";")[0].strip().lower() not in {
                "text/html", "application/xhtml+xml"}:
            raise SandboxError("Invalid offline resource bundle")
        body = item["body"]
        if not isinstance(body, str) or len(body) > ((RESOURCE_LIMIT + 2) // 3) * 4:
            raise SandboxError("Invalid offline resource bundle")
        try:
            decoded = base64.b64decode(body, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SandboxError("Invalid offline resource bundle") from error
        total += len(decoded)
        if len(decoded) > RESOURCE_LIMIT or total > BUNDLE_LIMIT:
            raise SandboxError("Offline resource bundle exceeded its limit")
        if base64.b64encode(decoded).decode("ascii") != body:
            raise SandboxError("Invalid offline resource bundle")
    payload = json.dumps(bundle, separators=(",", ":"), sort_keys=True, ensure_ascii=True,
                         allow_nan=False).encode("utf-8")
    if len(payload) > CAPTURE_OUTPUT:
        raise SandboxError("Offline resource bundle exceeded its limit")
    return payload


def _remove(docker: list[str], name: str) -> bool:
    """A successful removal or a successful empty exact-name lookup confirms disposal."""
    for _ in range(2):
        try:
            removed = subprocess.run([*docker, "rm", "-f", name], timeout=3, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            if removed.returncode == 0:
                return True
            check = subprocess.run([*docker, "ps", "--all", "--filter", "name=^/" + name + "$",
                                    "--format", "{{.Names}}"], timeout=3,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if check.returncode == 0 and not check.stdout.strip():
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    LOG.warning("sandbox_cleanup_unverified", extra={"container": name})
    return False


def _render(docker: list[str], payload: bytes, image_id: str, *, timeout: float = RUN_TIMEOUT) -> dict:
    name = "phishguard-" + uuid.uuid4().hex
    args = _run_args(docker, name, image_id)
    start = time.perf_counter()
    try:
        result = _exchange(args, payload, min(RUN_TIMEOUT, timeout), WORKER_OUTPUT, "Isolated browser")
        runtime = round((time.perf_counter() - start) * 1000, 2)
    finally:
        removed = _remove(docker, name)
    if not removed:
        raise SandboxError("Sandbox cleanup verification failed")
    result["capture"] = {"bundle_sha256": hashlib.sha256(payload).hexdigest(), "image_id": image_id}
    result.setdefault("performance", {})["container_run_ms"] = runtime
    return result


def _run_worker(docker: list[str], bundle: dict, image_id: str | None = None, *, timeout: float = RUN_TIMEOUT) -> dict:
    payload = encode_replay_bundle(bundle)
    return _render(docker, payload, image_id or _preflight(docker), timeout=timeout)


def replay_capture(bundle: dict, *, expected_image_id: str | None = None) -> dict:
    """Run a private capture through the same offline worker without resolving or fetching its URLs."""
    start = time.perf_counter()
    payload = encode_replay_bundle(bundle)
    with tempfile.TemporaryDirectory(prefix="phishguard-docker-") as config:
        docker = _docker(config)
        image_id = _preflight(docker)
        if expected_image_id is not None and image_id != expected_image_id:
            raise SandboxError("Local browser image differs from the original capture")
        result = _render(docker, payload, image_id)
        result.pop("_missing_resources", None)
        result["performance"]["replay_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return result


def run_sandbox(url: str, mode: str = "analyze") -> dict:
    url = validate_url(url)
    if mode not in MODES:
        raise SandboxError("Unknown analysis mode")
    with tempfile.TemporaryDirectory(prefix="phishguard-docker-") as config:
        docker = _docker(config)
        image_id = _preflight(docker)
        start = time.perf_counter()
        captured = _exchange(
            [sys.executable, "-m", "src.sandbox.isolation_capture"],
            json.dumps(url).encode("utf-8"), CAPTURE_TIMEOUT, CAPTURE_OUTPUT, "HTTP capture",
        )
        capture_ms = round((time.perf_counter() - start) * 1000, 2)
        if "error" in captured:
            failure = SandboxTimeout if captured.get("timeout") else SandboxError
            raise failure(captured["error"])
        if not isinstance(captured.get("capture"), dict) or not isinstance(captured.get("broker_trace"), list):
            raise SandboxError("Invalid offline resource bundle")
        # A disconnected passive run discovers resource URLs without any live
        # browser connection. Only the restricted HTTP broker can add bytes.
        deadline = start + 240
        discovery_ms = 0
        for attempt in range(3):
            bundle = {"url": captured["url"], "resources": captured["resources"], "mode": "javascript-analysis"}
            stage = time.perf_counter()
            remaining = deadline - stage
            if remaining <= 0:
                raise SandboxTimeout("Resource discovery exceeded its execution deadline")
            result = _run_worker(docker, bundle, image_id, timeout=min(60, remaining))
            discovery_ms += (time.perf_counter() - stage) * 1000
            missing = result.pop("_missing_resources", [])
            if not missing or attempt == 2 or deadline - time.perf_counter() < 45:
                break
            stage = time.perf_counter()
            supplement = _exchange(
                [sys.executable, "-m", "src.sandbox.isolation_capture"],
                json.dumps({"operation": "supplement", "capture": captured, "candidates": missing},
                           separators=(",", ":")).encode("utf-8"),
                15, CAPTURE_OUTPUT, "Resource capture",
            )
            capture_ms += (time.perf_counter() - stage) * 1000
            if "error" in supplement:
                captured["capture"].setdefault("omissions", {})["resource_supplement_failed"] = 1
                break
            if (supplement.get("url") != captured["url"] or not isinstance(supplement.get("resources"), dict)
                    or not isinstance(supplement.get("capture"), dict)
                    or not isinstance(supplement.get("broker_trace"), list)):
                raise SandboxError("Invalid offline resource bundle")
            grew = len(supplement["resources"]) > len(captured["resources"])
            captured = supplement
            if not grew:
                break
        bundle = {"url": captured["url"], "resources": captured["resources"], "mode": mode}
        if mode != "javascript-analysis":
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise SandboxTimeout("Resource discovery exceeded its execution deadline")
            result = _run_worker(docker, bundle, image_id, timeout=remaining)
            result.pop("_missing_resources", None)
        result["performance"]["capture_ms"] = capture_ms
        result["performance"]["resource_discovery_ms"] = round(discovery_ms, 2)
        result.update(url=url.partition("?")[0], capture={**captured["capture"], **result["capture"]},
                      broker_trace=captured["broker_trace"], _replay_bundle=bundle)
        return result
