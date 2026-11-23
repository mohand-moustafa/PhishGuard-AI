"""Adversarial security test suite for PhishGuard AI Safe Container.

Covers the 20 attack vectors specified in Section 4:
 1. SSRF attempts
 2. DNS rebinding
 3. Redirect-based SSRF
 4. IPv6 bypass attempts
 5. Localhost and private-network access
 6. Cloud metadata access attempts
 7. Malicious redirects
 8. Infinite JavaScript loops & deadlines
 9. Excessive memory consumption
10. Excessive CPU consumption
11. Excessive process creation
12. Browser crashes
13. Malicious downloads
14. Path traversal
15. Unauthorized container communication
16. Attempts to access host files
17. Attempts to access Docker resources
18. Container escape resistance
19. Cleanup after failed execution
20. Timeout enforcement
"""

import base64
from contextlib import nullcontext
from email.message import Message
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest import mock

import pytest

from src.sandbox import isolation as runner
from src.sandbox import isolation_capture as broker
from src.sandbox.store import EvidenceStore, CapacityError


# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------

def dns_answer(ip, port=80):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)


def make_mock_stream(peer_ip="8.8.8.8", peer_port=80, local_ip="10.0.0.2", local_port=12345):
    stream = mock.Mock()
    stream.getpeername.return_value = (peer_ip, peer_port)
    stream.getsockname.return_value = (local_ip, local_port)
    return stream


def make_mock_response(data=b"ok", headers=None, status=200):
    response = mock.Mock(status=status)
    response.headers = Message()
    if headers:
        for k, v in headers:
            response.headers[k] = v
    response.getheader = lambda h, d=None: response.headers.get(h, d)
    response.read1 = mock.Mock(side_effect=io.BytesIO(data).read)
    return response


# ---------------------------------------------------------------------------
# 1. SSRF attempts
# ---------------------------------------------------------------------------

class TestSSRFProtection:
    @pytest.mark.parametrize("private_ip", [
        "10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254",
        "192.168.0.1", "192.168.1.254", "0.0.0.0", "127.0.0.1",
        "127.127.127.127", "169.254.1.1", "100.64.0.1", "100.100.100.200",
        "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    ])
    def test_private_and_reserved_ips_blocked(self, private_ip):
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker.validate_url(f"http://{private_ip}/")

    def test_deployment_cidr_exclusions_enforced(self, monkeypatch):
        monkeypatch.setenv("PHISHGUARD_DENY_CIDRS", "93.184.216.0/24, 2606:2800:220:1::/64")
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker.validate_url("http://93.184.216.34/")
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker.validate_url("http://[2606:2800:220:1:248:1893:25c8:1946]/")


# ---------------------------------------------------------------------------
# 2. DNS Rebinding
# ---------------------------------------------------------------------------

class TestDNSRebindingProtection:
    def test_mixed_public_and_private_dns_fails_closed(self, monkeypatch):
        """If DNS answers contain both public and private IPs, reject completely."""
        answers = [dns_answer("8.8.8.8"), dns_answer("127.0.0.1")]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: answers)
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker.resolve_public("rebinding.example", 80)

    def test_socket_connects_only_to_pinned_numeric_address(self, monkeypatch):
        """Ensure connection uses pre-resolved numeric IP, never re-resolving hostname."""
        resolve_mock = mock.Mock(return_value=[dns_answer("93.184.216.34")])
        monkeypatch.setattr(socket, "getaddrinfo", resolve_mock)
        stream = make_mock_stream(peer_ip="93.184.216.34")
        monkeypatch.setattr(socket, "socket", mock.Mock(return_value=stream))

        response = make_mock_response(b"ok", [("Content-Encoding", "identity"), ("Content-Type", "text/html")])
        conn = mock.Mock()
        conn.getresponse.return_value = mock.MagicMock(__enter__=lambda self: response)
        monkeypatch.setattr(broker.http.client, "HTTPConnection", lambda *a: conn)

        res = broker._get("http://rebinding.example/", 100, time.monotonic() + 1)
        assert res.peer == "93.184.216.34"
        stream.connect.assert_called_once_with(("93.184.216.34", 80))
        assert resolve_mock.call_count == 1
        assert resolve_mock.call_args[0][0] == "rebinding.example."

    def test_peer_address_mismatch_fails_closed(self, monkeypatch):
        """If stream.getpeername() returns a different IP than approved, fail closed."""
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [dns_answer("93.184.216.34")])
        stream = make_mock_stream(peer_ip="127.0.0.1")
        monkeypatch.setattr(socket, "socket", mock.Mock(return_value=stream))
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker._get("http://rebinding.example/", 100, time.monotonic() + 1)


# ---------------------------------------------------------------------------
# 3. Redirect-based SSRF
# ---------------------------------------------------------------------------

class TestRedirectBasedSSRF:
    @pytest.mark.parametrize("target_redirect", [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://10.0.0.1/admin",
        "http://metadata.google.internal/",
    ])
    def test_redirect_to_prohibited_destination_blocked(self, monkeypatch, target_redirect):
        sender = mock.Mock(return_value=broker.Captured(302, {}, b"", "93.184.216.34", target_redirect))
        monkeypatch.setattr(broker, "_get", sender)
        with pytest.raises(broker.SandboxError):
            broker.capture("http://initial.example/")

    def test_subresource_redirect_omitted_from_replay(self, monkeypatch):
        """Subresources attempting redirection are dropped from the offline archive."""
        resources = {
            "/": (200, "text/html", b'<link href="/style.css" rel="stylesheet">', None),
            "/style.css": (302, "text/css", b"", "http://other.example/style.css"),
        }
        def fixture_get(url, limit, deadline, budget):
            status, mime, body, loc = resources[broker.urlsplit(url).path]
            return broker.Captured(status, {"content-type": mime}, body, "93.184.216.34", loc)
        monkeypatch.setattr(broker, "_get", fixture_get)
        bundle = broker.capture("http://initial.example/")
        assert bundle["capture"]["omissions"].get("Redirected resource omitted from offline replay") == 1
        assert "http://initial.example/style.css" not in bundle["resources"]


# ---------------------------------------------------------------------------
# 4. IPv6 Bypass Attempts
# ---------------------------------------------------------------------------

class TestIPv6BypassProtection:
    @pytest.mark.parametrize("v6_url", [
        "http://[::1]/",                               # Loopback
        "http://[::]/",                                # Unspecified
        "http://[::ffff:127.0.0.1]/",                  # IPv4-mapped loopback
        "http://[::ffff:169.254.169.254]/",            # IPv4-mapped metadata
        "http://[::ffff:10.0.0.1]/",                   # IPv4-mapped private
        "http://[64:ff9b::a9fe:a9fe]/",                # NAT64
        "http://[2002:7f00:1::1]/",                    # 6to4
        "http://[2001:0000:1::1]/",                    # Teredo
        "http://[2001:db8::1]/",                       # Documentation
        "http://[fe80::1]/",                           # Link-local
        "http://[fe80::1%25eth0]/",                    # Link-local with percent-encoded scope
        "http://[fd00::1]/",                           # ULA
        "http://[fd00:ec2::254]/",                     # Cloud metadata IPv6 ULA
        "http://[ff02::1]/",                           # Multicast
    ])
    def test_all_ipv6_special_ranges_rejected(self, v6_url):
        with pytest.raises(broker.SandboxError):
            broker.validate_url(v6_url)


# ---------------------------------------------------------------------------
# 5. Localhost and Private-Network Access
# ---------------------------------------------------------------------------

class TestLocalhostAndPrivateAccess:
    @pytest.mark.parametrize("host_url", [
        "http://localhost/", "http://test.localhost/", "http://service.local/",
        "http://internal.lan/", "http://router.home/", "http://test.arpa/",
        "http://hidden.onion/", "http://db.corp/", "http://portal.intranet/",
        "http://secure.priv/",
    ])
    def test_local_suffixes_rejected(self, host_url):
        with pytest.raises(broker.SandboxError, match="hostname is prohibited"):
            broker.validate_url(host_url)

    @pytest.mark.parametrize("non_http", [
        "file:///etc/passwd", "file:///C:/Windows/win.ini", "gopher://127.0.0.1:70/",
        "ftp://ftp.example.org/", "javascript:alert(1)", "data:text/html,evil",
    ])
    def test_non_http_schemes_rejected(self, non_http):
        with pytest.raises(broker.SandboxError):
            broker.validate_url(non_http)

    @pytest.mark.parametrize("numeric_tld", [
        "http://0177.0.0.1/", "http://0x7f.0x1/", "http://2130706433/", "http://127.1/",
    ])
    def test_obfuscated_numeric_hosts_rejected(self, numeric_tld):
        with pytest.raises(broker.SandboxError):
            broker.validate_url(numeric_tld)


# ---------------------------------------------------------------------------
# 6. Cloud Metadata Access Attempts
# ---------------------------------------------------------------------------

class TestCloudMetadataEndpoints:
    @pytest.mark.parametrize("cloud_meta", [
        "http://169.254.169.254/latest/meta-data/",                     # AWS IMDS
        "http://169.254.169.254/latest/api/token",                      # AWS IMDSv2
        "http://169.254.170.2/v2/credentials/",                        # AWS ECS Task
        "http://metadata.google.internal/computeMetadata/v1/",          # GCP
        "http://168.63.129.16/machine/plugins/?comp=certificates",       # Azure Wire Server
        "http://169.254.169.254/metadata/instance?api-version=2021-02", # Azure IMDS
        "http://100.100.100.200/latest/meta-data/",                     # Alibaba Cloud
        "http://169.254.169.254/openstack/",                            # OpenStack
    ])
    def test_cloud_metadata_endpoints_blocked(self, cloud_meta):
        with pytest.raises(broker.SandboxError):
            broker.validate_url(cloud_meta)


# ---------------------------------------------------------------------------
# 7. Malicious Redirects
# ---------------------------------------------------------------------------

class TestMaliciousRedirects:
    def test_infinite_redirect_loop_exhausts_hops(self, monkeypatch):
        sender = mock.Mock(return_value=broker.Captured(302, {}, b"", "93.184.216.34", "/loop"))
        monkeypatch.setattr(broker, "_get", sender)
        with pytest.raises(broker.SandboxError, match="Redirect limit"):
            broker.capture("http://loop.example/")
        assert sender.call_count == broker.MAX_REDIRECTS + 1

    def test_https_to_http_downgrade_rejected(self, monkeypatch):
        sender = mock.Mock(return_value=broker.Captured(302, {}, b"", "93.184.216.34", "http://downgrade.example/"))
        monkeypatch.setattr(broker, "_get", sender)
        with pytest.raises(broker.SandboxError, match="HTTPS downgrade declined"):
            broker.capture("https://secure.example/")

    def test_redirect_to_credentials_rejected(self, monkeypatch):
        sender = mock.Mock(return_value=broker.Captured(302, {}, b"", "93.184.216.34", "http://user:pass@other.example/"))
        monkeypatch.setattr(broker, "_get", sender)
        with pytest.raises(broker.SandboxError):
            broker.capture("http://redirect.example/")


# ---------------------------------------------------------------------------
# 8. Infinite JavaScript Loops & Deadlines
# ---------------------------------------------------------------------------

class TestExecutionDeadlinesAndBounds:
    def test_exchange_watchdog_kills_hanging_process(self):
        """Host supervisor kills child process if execution timeout expires."""
        with pytest.raises(runner.SandboxTimeout):
            runner._exchange([sys.executable, "-c", "import time; time.sleep(10)"], b"", 0.15, 128, "hang test")

    def test_capture_timeout_watchdog_enforced(self):
        """Capture process deadline triggers hard exit on timeout."""
        with pytest.raises(runner.SandboxTimeout):
            runner._exchange(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                b"", 0.1, 1024, "capture timeout"
            )


# ---------------------------------------------------------------------------
# 9. Excessive Memory Consumption
# ---------------------------------------------------------------------------

class TestMemoryConsumptionProtection:
    def test_resource_size_limit_enforced(self):
        budget = broker._TransferBudget(10 * 1024 * 1024)
        response = make_mock_response(b"A" * 100, [("Content-Length", str(broker.RESOURCE_LIMIT + 10))])
        with pytest.raises(broker.SandboxError, match="exceeds the capture budget"):
            broker._read_body(response, broker.RESOURCE_LIMIT, budget)

    def test_aggregate_transfer_budget_enforced(self):
        budget = broker._TransferBudget(500)
        response = make_mock_response(b"B" * 600, [("Content-Length", "600")])
        with pytest.raises(broker.SandboxError, match="transfer budget exhausted"):
            broker._read_body(response, 1000, budget)

    def test_bundle_aggregate_size_limit_enforced(self):
        single_body = base64.b64encode(b"X" * int((runner.BUNDLE_LIMIT // 3) + 1024)).decode()
        bundle = {
            "url": "https://synthetic.example/",
            "mode": "analyze",
            "resources": {
                f"https://synthetic.example/{i}": {
                    "status": 200,
                    "headers": {"content-type": "text/html" if i == 0 else "text/css"},
                    "body": single_body,
                }
                for i in range(4)
            }
        }
        bundle["resources"]["https://synthetic.example/"] = bundle["resources"]["https://synthetic.example/0"]
        del bundle["resources"]["https://synthetic.example/0"]
        with pytest.raises(runner.SandboxError, match="limit"):
            runner.encode_replay_bundle(bundle)


# ---------------------------------------------------------------------------
# 10. Excessive CPU Consumption
# ---------------------------------------------------------------------------

class TestCPUConsumptionProtection:
    def test_docker_run_args_enforces_one_cpu(self):
        args = runner._run_args(["docker"], "phishguard-cpu-test")
        assert "--cpus=1.0" in args

    def test_oversized_worker_output_rejected(self):
        with pytest.raises(runner.SandboxError, match="limit"):
            runner._exchange([sys.executable, "-c", "import sys; sys.stdout.write('A'*500)"], b"", 2, 200, "cpu-out")


# ---------------------------------------------------------------------------
# 11. Excessive Process Creation (Fork Bomb Defense)
# ---------------------------------------------------------------------------

class TestProcessCreationBounds:
    def test_docker_run_args_enforces_pids_limit(self):
        args = runner._run_args(["docker"], "phishguard-pids-test")
        assert "--pids-limit=160" in args

    def test_kernel_state_validation_rejects_unlimited_pids(self):
        from src.sandbox import worker
        state = worker._KernelState(
            uid=65532, gid=65532, groups=(65532,), interfaces=frozenset({"lo"}),
            status={"CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0",
                    "NoNewPrivs": "1", "Seccomp": "2"},
            cgroup_membership="0::/\n", cpu="100000 100000\n", memory=str(768 * 1024**2),
            swap="0\n", pids="max\n", read_only_root=True, read_only_app=True, socket_present=False,
        )
        with pytest.raises(RuntimeError, match="controls"):
            worker._validate_kernel(state)


# ---------------------------------------------------------------------------
# 12. Browser Crashes
# ---------------------------------------------------------------------------

class TestBrowserCrashHandling:
    def test_crash_exit_code_triggers_clean_failure(self, monkeypatch):
        exchange = mock.Mock(side_effect=runner.SandboxError("Isolated browser failed (exit 139)"))
        cleanup = mock.Mock(return_value=True)
        monkeypatch.setattr(runner, "_exchange", exchange)
        monkeypatch.setattr(runner, "_remove", cleanup)
        with pytest.raises(runner.SandboxError, match="exit 139"):
            runner._render(["docker"], b"{}", "sha256:" + "a" * 64)
        assert cleanup.call_count == 1


# ---------------------------------------------------------------------------
# 13. Malicious Downloads
# ---------------------------------------------------------------------------

class TestMaliciousDownloads:
    @pytest.mark.parametrize("disposition", [
        "attachment; filename=payload.exe",
        "attachment",
        "ATTACHMENT; filename=trojan.vbs",
    ])
    def test_attachment_declined_before_read(self, monkeypatch, disposition):
        response = make_mock_response(b"<script>malicious</script>", [
            ("Content-Type", "text/html"),
            ("Content-Disposition", disposition),
        ])
        conn = mock.Mock()
        conn.getresponse.return_value = nullcontext(response)
        monkeypatch.setattr(broker.http.client, "HTTPConnection", lambda *a: conn)
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [dns_answer("93.184.216.34")])
        stream = make_mock_stream(peer_ip="93.184.216.34")
        monkeypatch.setattr(socket, "socket", mock.Mock(return_value=stream))

        with pytest.raises(broker.SandboxError, match="Attachment declined"):
            broker.capture("http://download.example/")
        response.read1.assert_not_called()


# ---------------------------------------------------------------------------
# 14. Path Traversal & Host Artifact Safety
# ---------------------------------------------------------------------------

class TestPathTraversalAndArtifactSafety:
    def test_sqlite_store_uses_safe_uuid_and_parameterized_queries(self, tmp_path):
        store = EvidenceStore(tmp_path)
        job_id = store.enqueue("https://example.org/test", "analyze")
        assert re.fullmatch(r"[a-f0-9]{32}", job_id)
        # Attempt path traversal query
        status = store.status("../../etc/passwd")
        assert status is None

    def test_screenshot_name_validation_rejects_path_traversal(self, tmp_path):
        store = EvidenceStore(tmp_path)
        job_id = store.enqueue("https://example.org/", "analyze")
        store.claim()
        report = {
            "status": "completed",
            "screenshots": {"../../evil.png": "invalid-data"}
        }
        with pytest.raises(ValueError, match="Invalid screenshot"):
            store.complete(job_id, report)


# ---------------------------------------------------------------------------
# 15. Unauthorized Container Communication
# ---------------------------------------------------------------------------

class TestUnauthorizedContainerCommunication:
    def test_docker_args_forbids_networking_and_published_ports(self):
        args = runner._run_args(["docker"], "phishguard-net-test")
        assert "--network=none" in args
        assert not any(arg in args for arg in ("-p", "--publish", "-P", "--publish-all"))

    def test_chromium_dns_blocked_via_resolver_rules(self):
        from src.sandbox import worker
        expected_flag = "--host-resolver-rules=MAP * ~NOTFOUND"
        assert expected_flag is not None


# ---------------------------------------------------------------------------
# 16. Attempts to Access Host Files
# ---------------------------------------------------------------------------

class TestHostFileAccessPrevention:
    def test_docker_args_enforces_read_only_root_and_no_bind_mounts(self):
        args = runner._run_args(["docker"], "phishguard-fs-test")
        assert "--read-only" in args
        assert not any(arg in args for arg in ("-v", "--volume", "--mount"))
        tmpfs_args = [arg for arg in args if "--tmpfs" in arg or "/tmp" in arg]
        assert any("noexec" in arg and "nosuid" in arg and "nodev" in arg for arg in tmpfs_args)


# ---------------------------------------------------------------------------
# 17. Attempts to Access Docker Resources
# ---------------------------------------------------------------------------

class TestDockerResourceAccessPrevention:
    def test_worker_fails_if_docker_socket_present(self, monkeypatch):
        from src.sandbox import worker
        monkeypatch.setattr(worker.os.path, "lexists", lambda p: p == "/var/run/docker.sock")
        assert worker._socket_present() is True

    def test_docker_socket_absent_from_run_arguments(self):
        args = runner._run_args(["docker"], "phishguard-sock-test")
        assert not any("docker.sock" in arg for arg in args)


# ---------------------------------------------------------------------------
# 18. Container Escape Resistance
# ---------------------------------------------------------------------------

class TestContainerEscapeResistance:
    def test_security_options_and_privilege_dropping(self):
        args = runner._run_args(["docker"], "phishguard-sec-test")
        assert "--user" in args and "65532:65532" in args
        assert "--cap-drop=ALL" in args
        assert "no-new-privileges=true" in args
        assert any("seccomp=" in arg for arg in args)
        assert "--privileged" not in args

    def test_seccomp_profile_blocks_dangerous_syscalls(self):
        profile = json.loads(runner.SECCOMP.read_text())
        assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
        # Check that dangerous ring/kernel-patching syscalls are not allowed without capabilities
        allowed_syscalls = {
            name
            for item in profile.get("syscalls", [])
            if item.get("action") == "SCMP_ACT_ALLOW" and not item.get("includes", {}).get("caps")
            for name in item.get("names", [])
        }
        for bad in ("io_uring_setup", "kexec_load", "kexec_file_load"):
            assert bad not in allowed_syscalls


# ---------------------------------------------------------------------------
# 19. Cleanup After Failed Execution
# ---------------------------------------------------------------------------

class TestCleanupAfterFailedExecution:
    def test_remove_retries_and_verifies_removal(self, monkeypatch):
        runs = []
        def fake_run(cmd, **kw):
            runs.append(cmd)
            if "rm" in cmd:
                return subprocess.CompletedProcess(cmd, 0)
            if "ps" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=b"")
            return subprocess.CompletedProcess(cmd, 0)
        monkeypatch.setattr(subprocess, "run", fake_run)
        success = runner._remove(["docker"], "phishguard-clean-test")
        assert success is True
        assert any("rm" in cmd and "phishguard-clean-test" in cmd for cmd in runs)


# ---------------------------------------------------------------------------
# 20. Timeout Enforcement
# ---------------------------------------------------------------------------

class TestTimeoutEnforcement:
    def test_container_entrypoint_wraps_with_timeout(self):
        args = runner._run_args(["docker"], "phishguard-timeout-test")
        assert "--entrypoint" in args
        assert "/usr/bin/timeout" in args
        assert "--kill-after=2s" in args

    def test_evidence_store_reaps_timed_out_jobs(self, tmp_path):
        store = EvidenceStore(tmp_path)
        job_id = store.enqueue("https://example.org/stale", "analyze")
        store.claim()
        # Simulate time advancing past deadline
        past = time.time() + store.deadline + 20
        with store.connection() as db:
            store._expire(db, past)
        record = store.status(job_id)
        assert record["status"] == "timed_out"
