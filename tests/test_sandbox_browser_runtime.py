"""Host-independent checks of the worker's effective Linux preflight policy."""
from dataclasses import replace
from types import SimpleNamespace
import stat

import pytest

from src.sandbox import worker


BASELINE = worker._KernelState(
    uid=65532, gid=65532, groups=(65532,), interfaces=frozenset({"lo"}),
    status={"CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0",
            "NoNewPrivs": "1", "Seccomp": "2"},
    cgroup_membership="0::/\n", cpu="100000 100000\n", memory=str(768 * 1024**2),
    swap="0\n", pids="160\n", read_only_root=True, read_only_app=True, socket_present=False,
)


def test_effective_limits_allow_exact_and_tighter_budgets():
    worker._validate_kernel(BASELINE)
    worker._validate_kernel(replace(BASELINE, cpu="20000 100000", memory="268435456", pids="96"))


@pytest.mark.parametrize("change", [
    {"uid": 0}, {"gid": 0}, {"groups": (65532, 0)}, {"interfaces": frozenset({"lo", "eth0"})},
    {"read_only_root": False}, {"read_only_app": False}, {"socket_present": True},
    {"cgroup_membership": "0::/host.slice"}, {"cgroup_membership": "1:memory:/"},
    {"cpu": "max 100000"}, {"cpu": "200000 100000"}, {"cpu": "0 100000"}, {"cpu": ""},
    {"memory": "max"}, {"memory": str(768 * 1024**2 + 1)}, {"swap": "max"}, {"swap": "1"},
    {"pids": "max"}, {"pids": "161"}, {"status": {}},
    *[{"status": {**BASELINE.status, key: "0000000000000001"}} for key in
      ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")],
    {"status": {**BASELINE.status, "NoNewPrivs": "0"}}, {"status": {**BASELINE.status, "Seccomp": "0"}},
])
def test_worker_rejects_missing_or_weaker_control(change):
    with pytest.raises(RuntimeError):
        worker._validate_kernel(replace(BASELINE, **change))


def test_socket_bind_at_unusual_mount_path_is_rejected(monkeypatch):
    monkeypatch.setattr(worker.os.path, "lexists", lambda _: False)
    monkeypatch.setattr(worker.Path, "read_text", lambda _: "32 10 0:9 / /tmp/test\\040socket rw - ext4 / rw\n")
    seen = []
    def mounted_file(path):
        seen.append(path)
        return SimpleNamespace(st_mode=stat.S_IFSOCK)
    monkeypatch.setattr(worker.os, "stat", mounted_file)
    assert worker._socket_present()
    assert seen == ["/tmp/test socket"]


def test_preflight_failure_precedes_stdin_or_browser_import(monkeypatch):
    def reject():
        raise RuntimeError("Synthetic preflight denial")
    monkeypatch.setattr(worker, "verify_runtime", reject)
    monkeypatch.setattr(worker.sys, "stdin", None)
    assert worker.main() == 78


def test_optional_cgroup_usage_units_and_unavailable_counters(monkeypatch):
    counters = {"cpu.stat": "usage_usec 1532\nuser_usec 1230", "memory.peak": "123456"}
    monkeypatch.setattr(worker.Path, "read_text", lambda p: counters[p.name])
    assert worker._cgroup_usage() == {"container_cpu_ms": 1.53, "container_peak_memory_bytes": 123456}
    counters.update({"cpu.stat": "invalid", "memory.peak": "unavailable"})
    assert worker._cgroup_usage() == {"container_cpu_ms": None, "container_peak_memory_bytes": None}
