"""Offline broker, Docker policy, process bounds and cleanup tests. No public sites."""
import base64
from contextlib import nullcontext
from email.message import Message
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest import mock

import pytest

from src.sandbox import isolation as runner
from src.sandbox import isolation_capture as broker


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "javascript:void(0)", "ftp://example.org/", "http://localhost/",
    "https://metadata.google.internal/x", "http://example.org:8080", "http://x@8.8.8.8/",
    "http://127.0.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://[64:ff9b::a9fe:a9fe]/", "http://[2002:7f00:1::1]/",
    "http://[fe80::1%25eth0]/", "http://[fd00::1]/", "http://0.0.0.0/",
    "http://169.254.169.254/latest", "http://100.100.100.200/latest/",
    "http://168.63.129.16/", "http://198.18.0.1/", "http://224.0.0.1/",
    "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.0.1/",
    "http://0177.0.0.1/", "http://0x7f.0x1/", "http://2130706433/", "http://127.1/",
    "https://exa%mple.org/", "http://example.org\\@127.0.0.1/", "http://safe.example/a\nb",
    "http://[2606:4700::1]extra/",
    "https://[::]/", "https://[ff02::1]/", "https://192.0.0.8/", "https://[2001:0000:1::1]/",
    "http://192.0.2.1/", "http://198.51.100.3/", "http://203.0.113.5/", "http://255.255.255.255/",
])
def test_url_policy(url):
    with pytest.raises(broker.SandboxError):
        broker.validate_url(url)


def test_public_url_canonicalization_and_deployment_cidrs(monkeypatch):
    assert broker.validate_url("https://Example.Org.:443/hello#tab") == "https://example.org/hello"
    assert broker.validate_url("https://xn--bcher-kva.example/ü") == "https://xn--bcher-kva.example/%C3%BC"
    monkeypatch.setenv("PHISHGUARD_DENY_CIDRS", "8.8.8.0/24, 2606:4700::/32")
    with pytest.raises(broker.SandboxError):
        broker.validate_url("https://8.8.8.8/")
    with pytest.raises(broker.SandboxError):
        broker.validate_url("https://[2606:4700::1]/")


def dns_answer(ip):
    return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 80)


def resource():
    return {"status": 200, "headers": {"content-type": "text/html"}, "body": "eA=="}


def fake_response(data, headers):
    response = mock.Mock(status=200)
    response.headers = Message()
    for name, value in headers:
        response.headers[name] = value
    response.getheader = response.headers.get
    response.read1 = mock.Mock(side_effect=io.BytesIO(data).read)
    return response


def connect_fixture(monkeypatch, response):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        dns_answer("8.8.8.8"), dns_answer("1.1.1.1")])
    stream = mock.Mock()
    stream.getpeername.return_value = ("8.8.8.8", 80)
    stream.getsockname.return_value = ("10.0.0.2", 12345)
    monkeypatch.setattr(socket, "socket", mock.Mock(return_value=stream))
    conn = mock.Mock()
    conn.getresponse.return_value = nullcontext(response)
    monkeypatch.setattr(broker.http.client, "HTTPConnection", lambda *a: conn)
    return conn


@pytest.mark.parametrize("headers", [
    [("Content-Disposition", "Attachment; filename=fixture.html")],
    [("Content-Disposition", "inline"), ("Content-Disposition", "attachment")],
    [("Content-Disposition", "unknown-disposition")],
])
def test_attachment_never_read_or_executed(monkeypatch, headers):
    response = fake_response(b"<p>inert</p>", [("Content-Type", "text/html"), *headers])
    conn = connect_fixture(monkeypatch, response)
    with pytest.raises(broker.SandboxError, match="Attachment declined"):
        broker.capture("http://synthetic.example/")
    response.read1.assert_not_called()
    assert conn.request.call_count == 1


def test_explicit_inline_is_permitted(monkeypatch):
    response = fake_response(b"<p>fixture</p>", [("Content-Type", "text/html"),
                                                ("Content-Disposition", "inline; filename=fixture.html")])
    connect_fixture(monkeypatch, response)
    assert broker.capture("http://synthetic.example/")["capture"]["resource_count"] == 1


def test_failed_read_charged_and_never_resends_get(monkeypatch):
    response = fake_response(b"ab", [("Content-Length", "7")])
    conn = connect_fixture(monkeypatch, response)
    budget = broker._TransferBudget(9)
    with pytest.raises(broker.SandboxError, match="Incomplete"):
        broker._get("http://synthetic.example/", 8, time.monotonic() + 1, budget)
    assert budget.remaining == 7
    assert conn.request.call_count == 1


def test_request_timeout_is_reported_without_resending(monkeypatch):
    response = fake_response(b"", [])
    response.read1.side_effect = TimeoutError()
    conn = connect_fixture(monkeypatch, response)
    with pytest.raises(broker.SandboxTimeout):
        broker.capture("http://synthetic.example/")
    assert conn.request.call_count == 1


def test_transfer_limit_counts_omitted_resources():
    budget = broker._TransferBudget(7)
    with pytest.raises(broker.SandboxError, match="exceeds"):
        broker._read_body(fake_response(b"abcd", []), 3, budget)
    assert budget.remaining == 3
    with pytest.raises(broker.SandboxError, match="transfer budget"):
        broker._read_body(fake_response(b"more data", []), 10, budget)
    assert budget.remaining == 0


@pytest.mark.parametrize("headers", [[("Content-Length", "5"), ("Transfer-Encoding", "chunked")],
                                     [("Content-Range", "bytes 10-14/32")], [("Content-Length", "-1")]])
def test_invalid_or_partial_framing_is_rejected_before_body(headers):
    response = fake_response(b"hello", headers)
    with pytest.raises(broker.SandboxError, match="framing"):
        broker._read_body(response, 100, broker._TransferBudget(100))
    response.read1.assert_not_called()


def test_mixed_dns_answers_fail_before_connection(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [dns_answer("8.8.8.8"), dns_answer("10.1.2.3")])
    with mock.patch.object(socket, "socket", side_effect=AssertionError("No connect is permitted")):
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker._get("http://synthetic.example/", 128, time.monotonic() + 1)


def test_ipv6_and_ipv4_dns_results_are_all_validated(monkeypatch):
    host = "2606:4700:4700::1111"
    assert broker.validate_url(f"https://[{host}]/") == f"https://[{host}]/"
    answers = [dns_answer("8.8.8.8"),
               (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, 443, 0, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: list(answers))
    assert broker.resolve_public("synthetic.example", 443)[-1] == (socket.AF_INET6, (host, 443))
    answers.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("fd00::a", 443, 0, 0)))
    with pytest.raises(broker.SandboxError, match="prohibited"):
        broker.resolve_public("synthetic.example", 443)


def test_truncated_chunked_message_is_declined_by_http_parser():
    class SyntheticStream:
        def makefile(self, *args):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc")

    with broker.http.client.HTTPResponse(SyntheticStream()) as response:
        response.begin()
        budget = broker._TransferBudget(16)
        with pytest.raises(broker.SandboxError, match="Incomplete"):
            broker._read_body(response, 10, budget)
        assert budget.remaining == 13


def test_pinned_connection_and_rebinding(monkeypatch):
    resolve = mock.Mock(side_effect=[[dns_answer("8.8.8.8")], [dns_answer("127.0.0.1")]])
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    stream = mock.Mock()
    stream.getpeername.return_value = ("8.8.8.8", 80)
    stream.getsockname.return_value = ("10.0.0.2", 12345)
    monkeypatch.setattr(socket, "socket", mock.Mock(return_value=stream))
    response = mock.MagicMock(status=200)
    response.getheader.side_effect = lambda name, default=None: default
    response.read1.side_effect = [b"ok", b""]
    conn = mock.Mock()
    conn.getresponse.return_value = mock.MagicMock(__enter__=lambda self: response)
    monkeypatch.setattr(broker.http.client, "HTTPConnection", lambda *a: conn)
    first = broker._get("http://synthetic.example/", 50, time.monotonic() + 1)
    assert first.peer == "8.8.8.8"
    stream.connect.assert_called_once_with(("8.8.8.8", 80))
    assert resolve.call_count == 1
    assert resolve.call_args.args[0] == "synthetic.example."
    assert conn.auto_open == 0
    assert conn.request.call_args.kwargs["headers"]["Host"] == "synthetic.example"
    with pytest.raises(broker.SandboxError, match="prohibited"):
        broker._get("http://synthetic.example/resource", 50, time.monotonic() + 1)
    assert stream.connect.call_count == 1


def test_public_self_address_refused_before_http(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [dns_answer("8.8.8.8")])
    stream = mock.Mock()
    stream.getpeername.return_value = ("8.8.8.8", 80)
    stream.getsockname.return_value = ("8.8.8.8", 12345)
    monkeypatch.setattr(socket, "socket", mock.Mock(return_value=stream))
    with mock.patch.object(broker.http.client.HTTPConnection, "request") as send:
        with pytest.raises(broker.SandboxError, match="prohibited"):
            broker._get("http://synthetic.example/", 50, time.monotonic() + 1)
        send.assert_not_called()


def test_broker_trace_omits_query_values_and_authority_credentials():
    events = []
    broker._trace(events, url="https://user:password@site.example/root?token=private#fragment",
                  redirect="/somewhere?code=secret")
    assert events[0]["url"] == "https://site.example/root"
    assert events[0]["redirect"] == "/somewhere"
    assert "untrusted-string" not in broker.SandboxError("untrusted-string").public_message


def test_private_redirect_rejected_before_follow(monkeypatch):
    sender = mock.Mock(return_value=broker.Captured(302, {}, b"", "8.8.8.8", "http://169.254.169.254/"))
    monkeypatch.setattr(broker, "_get", sender)
    with pytest.raises(broker.SandboxError, match="prohibited"):
        broker.capture("http://synthetic.example/")
    assert sender.call_count == 1


def test_every_redirect_resolves_again(monkeypatch):
    sender = mock.Mock(side_effect=[
        broker.Captured(302, {}, b"", "8.8.8.8", "/next"),
        broker.SandboxError("Destination address is prohibited"),
    ])
    monkeypatch.setattr(broker, "_get", sender)
    with pytest.raises(broker.SandboxError, match="prohibited"):
        broker.capture("http://synthetic.example/")
    assert [args.args[0] for args in sender.call_args_list] == [
        "http://synthetic.example/", "http://synthetic.example/next",
    ]


def test_redirect_hop_bound_and_https_downgrade(monkeypatch):
    sender = mock.Mock(return_value=broker.Captured(302, {}, b"", "8.8.8.8", "/next"))
    monkeypatch.setattr(broker, "_get", sender)
    with pytest.raises(broker.SandboxError, match="Redirect limit"):
        broker.capture("https://synthetic.example/")
    assert sender.call_count == broker.MAX_REDIRECTS + 1
    sender.reset_mock()
    sender.return_value = broker.Captured(302, {}, b"", "8.8.8.8", "http://synthetic.example/")
    with pytest.raises(broker.SandboxError, match="downgrade"):
        broker.capture("https://synthetic.example/")
    assert sender.call_count == 1


def test_snapshot_collects_static_same_origin_only(monkeypatch):
    html = b"""<link href="/site.css" rel="stylesheet"><script src="/app.js"></script>
        <img src="https://third.example/pixel"><img src="/image"><form action="/submit"></form>"""
    resources = {
        "/": (200, "text/html", html, None),
        "/site.css": (200, "text/css", b"div{background:url('/icon')}", None),
        "/app.js": (200, "text/javascript", b"console.info('capture')", None),
        "/image": (302, "image/png", b"", "https://other.example/"),
        "/icon": (200, "image/png", b"x", None),
    }
    requests = []

    def fixture_get(url, limit, deadline, budget):
        assert url.startswith("https://site.example/")
        requests.append(url)
        status, mime, body, destination = resources[broker.urlsplit(url).path]
        return broker.Captured(status, {"content-type": mime}, body, "8.8.8.8", destination)

    monkeypatch.setattr(broker, "_get", fixture_get)
    snapshot = broker.capture("https://site.example/")
    assert snapshot["capture"]["resource_count"] == 4
    assert base64.b64decode(snapshot["resources"]["https://site.example/"]["body"]) == html
    assert any(item.get("blocked") for item in snapshot["broker_trace"])
    assert not any("submit" in url for url in requests)
    assert snapshot["capture"]["omissions"] == {
        "Cross-origin resource declined": 1, "Redirected resource omitted from offline replay": 1,
    }


def test_responsive_and_lazy_image_declarations_replay_from_same_origin(monkeypatch):
    origin = "https://site.example"
    html = b"""<template><base href="https://unused.example/"><img src="template.png"></template>
        <noscript><img srcset="/nojs 1x"></noscript><base href="/assets/">
        <picture><source srcset="small.webp 480w, big.webp 960w">
        <img src="small.png" srcset="small.png 1x, name,with,commas.png 2x"
             data-src="lazy.png" data-srcset="data:image/png;base64,AAAA 1x, lazy2.png 2x"></picture>
        <link rel="preload" as="image" href="small.png" imagesrcset="pre.png 1x">
        <link rel="preload" as="font" href="face.woff2"><link rel="modulepreload" href="component.js">
        <link rel="preload" as="fetch" href="ping"><a data-src="anchor"></a>
        <img srcset="malformed.png bad, //other.example/private 3x, http://127.0.0.1/test 1x">"""
    expected = {"small.webp", "big.webp", "small.png", "name,with,commas.png", "lazy.png",
                "lazy2.png", "pre.png", "face.woff2", "component.js", "template.png"}
    requests = []

    def fixture_get(url, limit, deadline, budget):
        requests.append(url)
        if url == origin + "/":
            return broker.Captured(200, {"content-type": "text/html"}, html, "8.8.8.8")
        assert url in {f"{origin}/assets/{name}" for name in expected}
        return broker.Captured(200, {"content-type": "application/octet-stream"}, b"fixture", "8.8.8.8")

    monkeypatch.setattr(broker, "_get", fixture_get)
    snapshot = broker.capture(origin + "/")
    assert set(requests) == {origin + "/"} | {f"{origin}/assets/{name}" for name in expected}
    assert len(requests) == len(snapshot["resources"]) == len(expected) + 1
    assert snapshot["capture"]["omissions"] == {"Cross-origin resource declined": 1,
                                                "invalid_or_prohibited_reference": 1}


def test_responsive_alternatives_share_existing_capture_budgets(monkeypatch):
    monkeypatch.setattr(broker, "MAX_ASSETS", 2)
    variants = ", ".join(f"/variant{i}.png {i+1}x" for i in range(30))
    html = f'<img srcset="{variants}"><script src="/app.js"></script><img src="/visible.png">'.encode()
    requested = []

    def fixture_get(url, limit, deadline, budget):
        requested.append(broker.urlsplit(url).path)
        if requested[-1] == "/":
            return broker.Captured(200, {"content-type": "text/html"}, html, "8.8.8.8")
        return broker.Captured(200, {"content-type": "application/octet-stream"}, b"x", "8.8.8.8")

    monkeypatch.setattr(broker, "_get", fixture_get)
    snapshot = broker.capture("https://site.example/")
    assert requested == ["/", "/app.js", "/visible.png"]
    assert snapshot["capture"]["omissions"]["bounded_html_references"] > 0
    assert snapshot["capture"]["omissions"]["pending_at_limit"] > 0


def test_local_fixture_server_receives_no_live_broker_requests():
    requests = []

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<button>Fixture</button>")

    with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(broker.SandboxError):
                broker.capture(f"http://127.0.0.1:{server.server_port}/fixture")
        finally:
            server.shutdown()
            thread.join()
    assert requests == []


def test_container_arguments_apply_disposable_limits(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_SANDBOX_RUNTIME", "runsc")
    args = runner._run_args(["docker"], "phishguard-unit")
    for setting in ("--rm", "--pull=never", "--init", "--network=none", "--ipc=private", "--read-only",
                    "--cap-drop=ALL", "no-new-privileges=true", "--cpus=1.0", "--pids-limit=160",
                    "--memory=768m", "--memory-swap=768m", "65532:65532", "--kill-after=2s", "runsc"):
        assert setting in args
    assert not {"--volume", "-v", "--privileged", "-p", "--publish", "--mount"}.intersection(args)
    profile = json.loads(runner.SECCOMP.read_text())
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    assert not any(item["action"] == "SCMP_ACT_ALLOW" and "io_uring_setup" in item["names"]
                   for item in profile["syscalls"])


@pytest.mark.parametrize("failure", [runner.SandboxError("crash"), runner.SandboxTimeout("deadline")])
def test_container_cleanup_on_worker_failure(monkeypatch, failure):
    exchange = mock.Mock(side_effect=failure)
    cleanup = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(runner, "_exchange", exchange)
    monkeypatch.setattr(subprocess, "run", cleanup)
    with pytest.raises(type(failure)):
        runner._render(["docker"], b"{}", "sha256:" + "a" * 64)
    args = exchange.call_args.args[0]
    assert cleanup.call_args.args[0] == ["docker", "rm", "-f", args[args.index("--name") + 1]]


def test_host_worker_timeout_and_oversized_protocol_are_bounded():
    with pytest.raises(runner.SandboxTimeout):
        runner._exchange([sys.executable, "-c", "import time; time.sleep(10)"], b"", 0.1, 128, "test")
    with pytest.raises(runner.SandboxError, match="limit"):
        runner._exchange([sys.executable, "-c", "print('x'*1024)"], b"", 3, 128, "test")


def test_unavailable_docker_prevents_capture(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    with mock.patch.object(runner, "_exchange", side_effect=AssertionError("capture started")):
        with pytest.raises(runner.SandboxError, match="Docker"):
            runner.run_sandbox("https://synthetic.example/")


@pytest.mark.parametrize("item", [
    {}, {"status": 200, "headers": {"content-type": "text/html"}}, {**resource(), "status": 302},
    {**resource(), "status": 206}, {**resource(), "status": True}, {**resource(), "body": "eA="},
    {**resource(), "body": "%%=="}, {**resource(), "body": "漢字"}, {**resource(), "body": "eP=="},
    {**resource(), "headers": {"content-type": "text/html", "set-cookie": "test=value"}},
    {**resource(), "headers": {"content-type": "text/html\r\nx:1"}},
    {**resource(), "headers": {"content-type": "application/zip"}}, {**resource(), "headers": []},
    {**resource(), "headers": {"content-type": "text/html", "content-disposition": "attachment"}},
])
def test_replay_rejects_damaged_or_unsafe_entry_before_docker(monkeypatch, item):
    url = "https://synthetic.example/"
    monkeypatch.setattr(runner, "_docker", mock.Mock(side_effect=AssertionError("Docker reached")))
    with pytest.raises(runner.SandboxError):
        runner.replay_capture({"url": url, "mode": "analyze", "resources": {url: item}})


@pytest.mark.parametrize("asset", [
    "https://synthetic.example/script#unmatched", "https://third.example/script",
    "http://synthetic.example/script", "https://127.0.0.1/script", "ftp://synthetic.example/script",
    "https://user@synthetic.example/script", "https://[fd00::1]/script",
])
def test_replay_validates_every_resource_without_dns(monkeypatch, asset):
    url = "https://synthetic.example/"
    monkeypatch.setattr(socket, "getaddrinfo", mock.Mock(side_effect=AssertionError("Unexpected DNS")))
    monkeypatch.setattr(runner, "_docker", mock.Mock(side_effect=AssertionError("Docker reached")))
    with pytest.raises(runner.SandboxError):
        runner.replay_capture({"url": url, "mode": "analyze", "resources": {url: resource(), asset: resource()}})


def test_archive_entry_and_aggregate_budgets(monkeypatch):
    url = "https://synthetic.example/"
    bundle = {"url": url, "mode": "analyze", "resources": {url: resource()}}
    monkeypatch.setattr(runner, "MAX_ASSETS", 1)
    monkeypatch.setattr(runner, "RESOURCE_LIMIT", 2)
    monkeypatch.setattr(runner, "BUNDLE_LIMIT", 2)
    bundle["resources"][url + "b"] = resource()
    assert runner.encode_replay_bundle(bundle)
    bundle["resources"][url + "c"] = resource()
    with pytest.raises(runner.SandboxError):
        runner.encode_replay_bundle(bundle)
    del bundle["resources"][url + "c"]
    bundle["resources"][url]["body"] = base64.b64encode(b"ab").decode()
    with pytest.raises(runner.SandboxError, match="limit"):
        runner.encode_replay_bundle(bundle)
    bundle["resources"][url]["body"] = base64.b64encode(b"abc").decode()
    with pytest.raises(runner.SandboxError):
        runner.encode_replay_bundle(bundle)


def test_cleanup_requires_positive_daemon_evidence(monkeypatch):
    good = subprocess.CompletedProcess([], 0, stdout=b"")
    failure = subprocess.CompletedProcess([], 1, stdout=b"")
    present = subprocess.CompletedProcess([], 0, stdout=b"phishguard-test\n")
    calls = mock.Mock(side_effect=[failure, present, failure, good])
    monkeypatch.setattr(subprocess, "run", calls)
    assert runner._remove(["docker"], "phishguard-test")
    assert calls.call_count == 4
    calls.side_effect = [failure, failure, failure, failure]
    assert not runner._remove(["docker"], "phishguard-test")


def test_replay_uses_canonical_snapshot_and_pinned_image_without_fetch(monkeypatch):
    url = "https://synthetic.example/"
    bundle = {"url": url, "mode": "analyze",
              "resources": {url: {"status": 200, "headers": {"content-type": "text/html"}, "body": "eA=="}}}
    image_id = "sha256:" + "a" * 64
    monkeypatch.setattr(runner, "_docker", lambda _: ["docker"])
    docker_call = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=image_id.encode() + b"\n"))
    monkeypatch.setattr(subprocess, "run", docker_call)
    capture = mock.Mock(side_effect=AssertionError("offline replay attempted a network request"))
    monkeypatch.setattr(broker, "_get", capture)
    monkeypatch.setattr(socket, "getaddrinfo", capture)
    calls = []

    def worker_only(args, payload, deadline, limit, label):
        assert label == "Isolated browser"
        calls.append((args, payload))
        return {"regions": []}

    monkeypatch.setattr(runner, "_exchange", worker_only)
    result = runner.replay_capture(bundle, expected_image_id=image_id)
    args, wire = calls[0]
    assert image_id in args and runner.IMAGE not in args and "--network=none" in args
    assert runner.encode_replay_bundle(bundle) == wire
    assert json.loads(wire) == bundle
    assert result["capture"] == {"image_id": image_id, "bundle_sha256": hashlib.sha256(wire).hexdigest()}
    assert result["performance"]["container_run_ms"] >= 0 and result["performance"]["replay_ms"] >= 0
    assert "capture_ms" not in result["performance"]
    assert "_replay_bundle" not in result
    assert docker_call.call_args_list[0].args[0] == ["docker", "image", "inspect", "--format", "{{.Id}}", runner.IMAGE]
    with pytest.raises(runner.SandboxError, match="differs"):
        runner.replay_capture(bundle, expected_image_id="sha256:" + "b" * 64)
    capture.assert_not_called()
    assert len(calls) == 1


def test_capture_returns_private_exact_worker_input_separate_from_trace(monkeypatch):
    url = "https://synthetic.example/"
    page = {"status": 200, "headers": {"content-type": "text/html"}, "body": "eA=="}
    monkeypatch.setattr(runner, "_docker", lambda _: ["docker"])
    monkeypatch.setattr(runner, "_preflight", lambda _: "sha256:" + "a" * 64)
    cleanup = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(subprocess, "run", cleanup)
    wire = []

    def exchange(command, payload, timeout, limit, label):
        if label == "HTTP capture":
            return {"url": url, "resources": {url: page}, "broker_trace": [{"method": "GET"}],
                    "capture": {"resource_count": 1}}
        wire.append(payload)
        return {"regions": []}

    monkeypatch.setattr(runner, "_exchange", exchange)
    result = runner.run_sandbox(url, "interaction-scan")
    assert result["_replay_bundle"] == {"url": url, "resources": {url: page}, "mode": "interaction-scan"}
    assert wire[-1] == runner.encode_replay_bundle(result["_replay_bundle"])
    assert result["capture"]["bundle_sha256"] == hashlib.sha256(wire[-1]).hexdigest()
    assert result["capture"]["resource_count"] == 1
    assert result["performance"]["capture_ms"] >= 0 and "replay_ms" not in result["performance"]
    assert result["broker_trace"] == [{"method": "GET"}]


@pytest.mark.skipif(os.getenv("PHISHGUARD_TEST_DOCKER") != "1",
                    reason="set PHISHGUARD_TEST_DOCKER=1 with local worker image")
@pytest.mark.parametrize("scenario", ["kernel", "crash", "timeout"])
def test_enforced_container_limits_and_no_egress(scenario):
    """Verify real kernel settings, crash/deadline disposal and zero external target traffic."""
    name = "phishguard-" + uuid.uuid4().hex
    probe = """
import json, os, pathlib, socket
from src.sandbox.worker import verify_runtime
verify_runtime()
p = pathlib.Path
status = dict(line.split(':',1) for line in p('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid() == 65532 and int(status['CapEff'],16) == 0
assert int(status['NoNewPrivs']) == 1 and int(status['Seccomp']) == 2
try:
    os.chroot('/')
except PermissionError:
    pass
else:
    raise AssertionError('Outer worker unexpectedly has chroot privileges')
assert not p('/var/run/docker.sock').exists()
assert set(os.listdir('/sys/class/net')) <= {'lo'}
assert os.statvfs('/app').f_flag & os.ST_RDONLY
assert p('/sys/fs/cgroup/pids.max').read_text().strip() == '160'
assert int(p('/sys/fs/cgroup/memory.max').read_text()) <= 768*1024**2
quota,period = map(int,p('/sys/fs/cgroup/cpu.max').read_text().split())
assert quota > 0 and quota <= period
try:
    socket.create_connection(('192.0.2.1',80),timeout=0.5).close()
except OSError:
    print(json.dumps({'isolated':True}))
else:
    raise AssertionError('network isolation failure')
"""
    with tempfile.TemporaryDirectory() as config:
        docker = runner._docker(config)
        image_id = runner._preflight(docker)
        args = runner._run_args(docker, name, image_id)
        command = args.index("python")
        if scenario == "crash":
            probe = "import sys; sys.exit(17)"
        elif scenario == "timeout":
            args[command - 1] = "1s"
            probe = "import time; time.sleep(10)"
        args[command:] = ["python", "-c", probe]
        try:
            if scenario == "kernel":
                assert runner._exchange(args, b"", 20, 128, "kernel probe") == {"isolated": True}
            elif scenario == "crash":
                with pytest.raises(runner.SandboxError, match="exit 17"):
                    runner._exchange(args, b"", 20, 128, "crash probe")
            else:
                with pytest.raises(runner.SandboxTimeout):
                    runner._exchange(args, b"", 20, 128, "deadline probe")
            # Check Docker's automatic disposal before the fallback removal in teardown.
            until = time.monotonic() + 4
            while time.monotonic() < until:
                result = subprocess.run([*docker, "ps", "-a", "--filter", f"name=^/{name}$",
                                         "--format", "{{.Names}}"], capture_output=True, timeout=3, check=True)
                if not result.stdout.strip():
                    break
                time.sleep(0.1)
            assert not result.stdout.strip()
        finally:
            subprocess.run([*docker, "rm", "-f", name], capture_output=True, timeout=5)
        result = subprocess.run([*docker, "container", "inspect", name], capture_output=True, timeout=5)
        assert result.returncode != 0
