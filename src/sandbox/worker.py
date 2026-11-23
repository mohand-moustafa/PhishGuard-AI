"""JSON stdin/stdout entry point for the disposable network-disabled container."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class _KernelState:
    uid: int
    gid: int
    groups: tuple[int, ...]
    interfaces: frozenset[str]
    status: dict[str, str]
    cgroup_membership: str
    cpu: str
    memory: str
    swap: str
    pids: str
    read_only_root: bool
    read_only_app: bool
    socket_present: bool


def _validate_kernel(state: _KernelState) -> None:
    if (state.uid != 65532 or state.gid != 65532 or set(state.groups) - {65532}
            or state.interfaces != {"lo"} or not state.read_only_root or not state.read_only_app
            or state.socket_present or state.cgroup_membership.strip() != "0::/"):
        raise RuntimeError("Worker identity, mounts, namespaces or network controls do not match")
    try:
        capabilities = (int(state.status[name], 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        if any(capabilities) or int(state.status["NoNewPrivs"]) != 1 or int(state.status["Seccomp"]) != 2:
            raise RuntimeError("Worker privilege controls do not match")
        # cgroup v2 writes 'max' to represent an unbounded resource. Parsing fails closed.
        quota, period = map(int, state.cpu.split())
        if (not 0 < quota <= period or not 0 < int(state.memory) <= 768 * 1024**2
                or int(state.swap) != 0 or not 0 < int(state.pids) <= 160):
            raise RuntimeError("Worker resource controls exceed the permitted limits")
    except (ValueError, KeyError) as exc:
        raise RuntimeError("Worker kernel controls are unavailable or unlimited") from exc


def _socket_present() -> bool:
    for socket_path in ("/var/run/docker.sock", "/run/docker.sock", "/run/user/65532/docker.sock"):
        if os.path.lexists(socket_path):
            return True
    # A socket bind-mounted under a different filename is still a socket inode.
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        encoded = line.split(" ", 5)[4]
        path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), encoded)
        if stat.S_ISSOCK(os.stat(path).st_mode):
            return True
    return False


def verify_runtime() -> None:
    """Fail before consuming page data unless the provisioned kernel controls are effective."""
    if sys.platform != "linux" or os.environ.get("PHISHGUARD_SANDBOX_WORKER") != "1":
        raise RuntimeError("Worker requires the sandbox image on Linux")
    cg = Path("/sys/fs/cgroup")
    try:
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        state = _KernelState(uid=os.geteuid(), gid=os.getegid(), groups=tuple(os.getgroups()),
                             interfaces=frozenset(os.listdir("/sys/class/net")), status=status,
                             cgroup_membership=Path("/proc/self/cgroup").read_text(),
                             cpu=(cg / "cpu.max").read_text(), memory=(cg / "memory.max").read_text(),
                             swap=(cg / "memory.swap.max").read_text(), pids=(cg / "pids.max").read_text(),
                             read_only_root=bool(os.statvfs("/").f_flag & os.ST_RDONLY),
                             read_only_app=bool(os.statvfs("/app").f_flag & os.ST_RDONLY),
                             socket_present=_socket_present())
    except (IndexError, ValueError, OSError) as exc:
        raise RuntimeError("Worker could not verify its effective kernel controls") from exc
    _validate_kernel(state)


def _cgroup_usage() -> dict:
    root = Path("/sys/fs/cgroup")
    usage = {"container_cpu_ms": None, "container_peak_memory_bytes": None}
    try:
        entries = dict(line.split() for line in (root / "cpu.stat").read_text().splitlines())
        usage["container_cpu_ms"] = round(int(entries["usage_usec"]) / 1000, 2)
    except (OSError, ValueError, KeyError):
        pass
    try:
        usage["container_peak_memory_bytes"] = int((root / "memory.peak").read_text())
    except (OSError, ValueError):
        pass
    return usage


def main() -> int:
    try:
        verify_runtime()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 78
    from playwright.sync_api import sync_playwright
    from .browser import SafeInteractionEngine

    limit = 24 * 1024 * 1024
    payload = sys.stdin.buffer.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Input budget exceeded")
    job = json.loads(payload)
    url, mode = job["url"], job["mode"]
    if mode not in {"analyze", "interaction-scan", "javascript-analysis"} or url not in job["resources"]:
        raise ValueError("Invalid worker request")
    with sync_playwright() as playwright:
        started = time.monotonic()
        browser = playwright.chromium.launch(headless=True, chromium_sandbox=True,
            args=["--disable-background-networking", "--disable-extensions",
                  "--host-resolver-rules=MAP * ~NOTFOUND", "--disable-quic",
                  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
        startup = round((time.monotonic() - started)*1000, 2)
        try:
            result = SafeInteractionEngine(browser, url, job["resources"]).analyze(mode)
        finally:
            browser.close()
    result.setdefault("performance", {}).update(browser_startup_ms=startup, **_cgroup_usage())
    encoded = json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode()
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError("Output budget exceeded")
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # Avoid leaking URLs, page content, credentials or execution paths in logs.
        print(f"Sandbox worker failed ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(1)
