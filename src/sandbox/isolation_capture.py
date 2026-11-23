"""Trusted, read-only HTTP capture. The browser never has a connection to this broker."""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from . import REPLAY_HEADERS


class SandboxError(Exception):
    """Safe-to-display reason for a rejected or failed scan."""

    @property
    def public_message(self) -> str:
        message = str(self)
        if message in {
            "Destination address is prohibited", "Destination port is prohibited",
            "Destination hostname is prohibited", "Destination DNS resolution failed",
            "Local Docker CLI is unavailable", "Local Docker is unavailable",
            "Local Docker daemon or phishguard-browser:local image is unavailable",
            "Public destination unavailable", "TLS certificate verification failed",
            "Destination did not return an HTML document", "Compressed response declined",
            "Response exceeds the capture budget", "HTTPS downgrade declined",
            "Invalid deployment network exclusion", "Redirect limit or invalid redirect",
            "Unknown sandbox runtime", "Invalid response headers",
            "Worker rejected effective kernel isolation or resource limits",
            "Local browser image differs from the original capture", "Invalid local Docker image identity",
            "Invalid offline resource bundle",
            "Attachment declined", "Incomplete HTTP response", "Unsupported HTTP response framing",
            "Capture transfer budget exhausted", "Sandbox cleanup verification failed",
        }:
            return message
        if re.fullmatch(r"Isolated browser failed \(exit [0-9-]{1,5}\)", message):
            return message + ". Verify the local image and Chromium user namespace policy."
        return "The isolated capture failed. Check the URL policy and local worker runtime."

class SandboxTimeout(SandboxError):
    """The bounded capture or isolated renderer exceeded its time budget."""


CAPTURE_TIMEOUT = 50
RESOURCE_LIMIT = 6 * 1024 * 1024
BUNDLE_LIMIT = 16 * 1024 * 1024
TRANSFER_LIMIT = 24 * 1024 * 1024
MAX_ASSETS = 48
MAX_REDIRECTS = 5
MAX_TRACE = 300
MAX_URL = 4096
MAX_IMAGE_VARIANTS = 8
SUPPLEMENT_TIMEOUT = 12
MAX_SUPPLEMENT_CANDIDATES = 12
MAX_SUPPLEMENT_ROUNDS = 2
CAPTURE_INPUT_LIMIT = 12 * 1024 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".arpa", ".onion", ".corp", ".intranet", ".priv")
# IPv4 exclusions also cover gaps between Python versions' IANA special-purpose tables.
_EXCLUDED = tuple(map(ipaddress.ip_network, (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.88.99.0/24",
    "168.63.129.16/32", "224.0.0.0/4", "240.0.0.0/4",
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
)))
_GLOBAL_V6 = ipaddress.ip_network("2000::/3")


def _check_address(value: str) -> None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as error:
        raise SandboxError("Invalid network address") from error
    try:
        extra = [ipaddress.ip_network(cidr.strip()) for cidr in
                 os.getenv("PHISHGUARD_DENY_CIDRS", "").split(",") if cidr.strip()]
    except ValueError as error:
        raise SandboxError("Invalid deployment network exclusion") from error
    if (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback
            or ip.is_private or ip.is_link_local or ip.is_unspecified
            or (ip.version == 6 and (ip not in _GLOBAL_V6 or ip.scope_id is not None))
            or any(ip in net for net in (*_EXCLUDED, *extra))):
        raise SandboxError("Destination address is prohibited")


def validate_url(url: str) -> str:
    """Validate browser URL syntax without network I/O. DNS and peer checks follow per request."""
    if (not isinstance(url, str) or not url or len(url) > MAX_URL or "\\" in url
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 or 0xD800 <= ord(ch) <= 0xDFFF
                   for ch in url)):
        raise SandboxError("Invalid HTTP URL")
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"https", "http"} or parts.username is not None or not parts.hostname:
            raise SandboxError("A public HTTP(S) URL without credentials is required")
        if "[" in parts.netloc and not re.fullmatch(r"\[[a-fA-F0-9:.]+\](?::[0-9]+)?", parts.netloc):
            raise SandboxError("Invalid URL authority")
        if parts.port not in (None, 443 if parts.scheme == "https" else 80):
            raise SandboxError("Destination port is prohibited")
        host = parts.hostname.removesuffix(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as error:
        raise SandboxError("Invalid URL authority") from error
    if "%" in host:
        raise SandboxError("Invalid URL host")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels)
                or host.endswith(_LOCAL_SUFFIXES) or labels[-1].isdigit()
                or re.fullmatch(r"0x[a-f0-9]+", labels[-1])):
            raise SandboxError("Destination hostname is prohibited")
    else:
        _check_address(str(literal))
        host = f"[{literal}]" if literal.version == 6 else str(literal)
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/?%:@!$&'()*+,;=-._~")
    canonical = urlunsplit((parts.scheme, host, path, query, ""))
    if len(canonical) > MAX_URL:
        raise SandboxError("URL exceeds the capture budget")
    return canonical


def resolve_public(host: str, port: int) -> list[tuple[int, tuple]]:
    """Reject mixed answers and use absolute DNS names to avoid search domains."""
    try:
        ipaddress.ip_address(host)
        name = host
    except ValueError:
        name = host + "."
    try:
        answers = socket.getaddrinfo(name, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError as error:
        raise SandboxError("Destination DNS resolution failed") from error
    if not answers:
        raise SandboxError("No public destination address")
    result = []
    for family, _, _, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise SandboxError("Unsupported address family")
        _check_address(address[0])
        # Reconstruct the socket address with the validated port, no interface scope.
        endpoint = (str(ipaddress.ip_address(address[0])), port)
        result.append((family, endpoint))
    return result


@dataclass
class Captured:
    status: int
    headers: dict[str, str]
    body: bytes
    peer: str
    location: str | None = None


@dataclass
class _TransferBudget:
    remaining: int


def valid_header(value: str) -> bool:
    return isinstance(value, str) and len(value) <= 8192 and all(
        ch == "\t" or 32 <= ord(ch) <= 255 and ord(ch) != 127 for ch in value)


def _read_body(response, limit: int, budget: _TransferBudget) -> bytes:
    """Charge decoded HTTP body bytes even when the resource is dropped or cut short."""
    length = response.getheader("Content-Length")
    encoding = response.getheader("Transfer-Encoding", "").lower()
    if (encoding and (encoding != "chunked" or length is not None)
            or response.status == 206 or response.getheader("Content-Range") is not None):
        raise SandboxError("Unsupported HTTP response framing")
    if length is not None and (not length.isascii() or not length.isdigit() or len(length) > 12):
        raise SandboxError("Unsupported HTTP response framing")
    expected = int(length) if length is not None else None
    if expected is not None and expected > limit:
        raise SandboxError("Response exceeds the capture budget")
    if expected is not None and expected > budget.remaining:
        raise SandboxError("Capture transfer budget exhausted")
    body = bytearray()
    while expected is None or len(body) < expected:
        if budget.remaining <= 0:
            raise SandboxError("Capture transfer budget exhausted")
        available = (limit + 1 if expected is None else expected) - len(body)
        try:
            chunk = response.read1(min(65536, budget.remaining, available))
        except http.client.IncompleteRead as exc:
            budget.remaining -= min(budget.remaining, len(exc.partial))
            raise SandboxError("Incomplete HTTP response") from exc
        if not chunk:
            break
        budget.remaining -= len(chunk)
        body.extend(chunk)
        if len(body) > limit:
            raise SandboxError("Response exceeds the capture budget")
    if expected is not None and len(body) != expected:
        raise SandboxError("Incomplete HTTP response")
    return bytes(body)


def _get(url: str, limit: int, deadline: float, budget: _TransferBudget | None = None) -> Captured:
    parts = urlsplit(url)
    host = parts.hostname
    port = 443 if parts.scheme == "https" else 80
    if budget is None:
        budget = _TransferBudget(TRANSFER_LIMIT)
    addresses = resolve_public(host, port)
    for family, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SandboxTimeout("HTTP capture timed out")
        # Connect to the validated numeric address. Never reconnect using the hostname.
        stream = socket.socket(family, socket.SOCK_STREAM)
        conn = http.client.HTTPConnection(host, port)
        request_started = False
        try:
            stream.settimeout(min(10.0, remaining))
            stream.connect(address)
            peer = stream.getpeername()[0]
            _check_address(peer)
            if ipaddress.ip_address(peer) != ipaddress.ip_address(address[0]):
                raise SandboxError("Connected peer does not match the approved address")
            if ipaddress.ip_address(stream.getsockname()[0]) == ipaddress.ip_address(peer):
                raise SandboxError("Destination address is prohibited")
            if parts.scheme == "https":
                try:
                    import certifi
                    ssl_ctx = ssl.create_default_context(cafile=certifi.where())
                except (ImportError, OSError):
                    ssl_ctx = ssl.create_default_context()
                stream = ssl_ctx.wrap_socket(stream, server_hostname=host)
            conn.sock = stream
            conn.auto_open = 0
            target = parts.path + ("?" + parts.query if parts.query else "")
            request_started = True
            conn.request("GET", target, headers={
                "Host": parts.netloc, "User-Agent": "PhishGuard-Offline-Capture/1",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            with conn.getresponse() as response:
                if response.status in REDIRECT_CODES:
                    return Captured(response.status, {}, b"", peer, response.getheader("Location"))
                disposition = response.getheader("Content-Disposition")
                if disposition is not None and (
                        len(response.headers.get_all("Content-Disposition", [])) != 1
                        or disposition.split(";", 1)[0].strip().lower() != "inline"):
                    raise SandboxError("Attachment declined")
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise SandboxError("Compressed response declined")
                body = _read_body(response, limit, budget)
                headers = {}
                for key in REPLAY_HEADERS:
                    value = response.getheader(key)
                    if value is not None:
                        if not valid_header(value):
                            raise SandboxError("Invalid response headers")
                        headers[key.lower()] = value
                return Captured(response.status, headers, body, peer)
        except ssl.SSLCertVerificationError as error:
            raise SandboxError("TLS certificate verification failed") from error
        except (OSError, http.client.HTTPException) as error:
            if request_started:
                # An HTTP GET may have side effects on the server. Never issue it again.
                if isinstance(error, TimeoutError):
                    raise SandboxTimeout("HTTP capture timed out") from error
                raise SandboxError("Incomplete HTTP response") from error
            continue
        finally:
            conn.close()
            stream.close()
    raise SandboxError("Public destination unavailable")


def _trace(events: list[dict], **record) -> None:
    if len(events) < MAX_TRACE:
        for key in ("url", "redirect"):
            if record.get(key):
                try:
                    parts = urlsplit(record[key])
                    authority = parts.netloc.rsplit("@", 1)[-1]
                    record[key] = urlunsplit((parts.scheme, authority, parts.path, "", ""))[:MAX_URL]
                except ValueError:
                    record[key] = "[invalid destination]"
        events.append({"timestamp": datetime.now(timezone.utc).isoformat(), "method": "GET",
                       "phase": "capture", **record})


def _fetch(url: str, *, origin: str | None, limit: int, deadline: float, budget: _TransferBudget,
           events: list[dict], attempted: set[str] | None = None) -> tuple[str, Captured]:
    for hop in range(MAX_REDIRECTS + 1):
        url = validate_url(url)
        parts = urlsplit(url)
        if origin is not None and f"{parts.scheme}://{parts.netloc}" != origin:
            raise SandboxError("Cross-origin resource declined")
        if attempted is not None:
            attempted.add(url)
        response = _get(url, limit, deadline, budget)
        redirect = response.location
        _trace(events, url=url, destination_domain=parts.hostname, peer=response.peer,
               status=response.status, redirect=redirect[:MAX_URL] if redirect else None)
        if response.status not in REDIRECT_CODES:
            return url, response
        if not response.location or len(response.location) > MAX_URL or hop == MAX_REDIRECTS:
            raise SandboxError("Redirect limit or invalid redirect")
        try:
            next_url = validate_url(urljoin(url, response.location))
        except ValueError as exc:
            raise SandboxError("Redirect limit or invalid redirect") from exc
        if parts.scheme == "https" and urlsplit(next_url).scheme != "https":
            raise SandboxError("HTTPS downgrade declined")
        if origin is not None:
            # Serving final bytes under the alias changes CSS, module and iframe base URLs.
            # Only the top-level navigation has a faithful final-URL representation.
            raise SandboxError("Redirected resource omitted from offline replay")
        url = next_url
    raise SandboxError("Redirect limit exceeded")


_SRCSET_URL = re.compile(r"[^, \t\n\r\f][^ \t\n\r\f]*")
_SRCSET_DESCRIPTOR = re.compile(r"(?:0*[1-9][0-9]*w|(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?x)")


class _AssetLinks(HTMLParser):
    # Chromium replays with scripting enabled. These elements contain text, not active tags.
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, "noscript", "textarea", "title")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.primary: dict[str, None] = {}
        self.additional: dict[str, None] = {}
        self.base: str | None = None
        self.overflow = 0
        self.template_depth = 0

    def add(self, value: str | None, *, additional: bool = False) -> None:
        if not value:
            return
        # Templates may be cloned later by archived scripts. Preserve their
        # declared assets without giving dormant content priority over the page.
        additional = additional or bool(self.template_depth)
        target = self.additional if additional else self.primary
        if value in target or (additional and value in self.primary):
            return
        if len(target) >= MAX_ASSETS * 4 or len(value) > MAX_URL:
            self.overflow += 1
            return
        if not additional:
            self.additional.pop(value, None)
        target[value] = None

    def add_srcset(self, value: str | None) -> None:
        if not value:
            return
        if len(value) > MAX_URL * MAX_IMAGE_VARIANTS:
            self.overflow += 1
            return
        # A URL runs up to ASCII whitespace. Commas within a URL (including a
        # data URI) are legal. Only trailing commas or descriptor commas delimit it.
        cursor = count = 0
        while match := _SRCSET_URL.search(value, cursor):
            url = match[0]
            cursor = match.end()
            if url.endswith(","):
                url = url.rstrip(",")
            else:
                end = value.find(",", cursor)
                descriptor = value[cursor:end if end >= 0 else len(value)].strip(" \t\n\r\f")
                cursor = end + 1 if end >= 0 else len(value)
                if "(" in descriptor:
                    # An unsupported descriptor may itself contain commas.
                    # Decline the rest rather than interpreting them as new URLs.
                    self.overflow += 1
                    break
                if descriptor and not _SRCSET_DESCRIPTOR.fullmatch(descriptor):
                    continue
            if url.lower().startswith("data:"):
                continue  # The browser already has these inline bytes in the document.
            if count >= MAX_IMAGE_VARIANTS:
                self.overflow += 1
                break
            self.add(url, additional=True)
            count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self.template_depth:
            self.template_depth -= 1

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "template":
            self.template_depth += 1
            return
        values = dict(attrs)
        if tag == "base" and not self.template_depth and self.base is None and values.get("href"):
            self.base = values["href"]
        if tag == "link":
            rel = (values.get("rel") or "").lower().split()
            kind = (values.get("as") or "").lower()
            if "stylesheet" in rel:
                self.add(values.get("href"))
            elif "modulepreload" in rel or ("preload" in rel and kind in {"image", "style", "script", "font"}):
                self.add(values.get("href"), additional=True)
                if kind == "image":
                    self.add_srcset(values.get("imagesrcset"))
        elif tag in {"script", "img", "iframe", "source"}:
            self.add(values.get("src"))
            if tag in {"img", "source"}:
                self.add_srcset(values.get("srcset"))
                self.add(values.get("data-src"), additional=True)
                self.add_srcset(values.get("data-srcset"))


def _links(resource: Captured, base: str, omissions: Counter) -> list[str]:
    mime = resource.headers.get("content-type", "").split(";")[0].lower().strip()
    links = []
    if mime in {"text/html", "application/xhtml+xml"}:
        parser = _AssetLinks()
        try:
            parser.feed(resource.body.decode("utf-8", errors="replace"))
            if parser.base:
                base = urljoin(base, parser.base)
        except (ValueError, AssertionError):
            omissions["markup_parse_incomplete"] += 1
        # A long responsive image list must not crowd out the page's direct
        # script, stylesheet or image references.
        links = [*parser.primary, *parser.additional]
        limit = MAX_ASSETS * 4
        overflow = parser.overflow + max(0, len(links) - limit)
        if overflow:
            omissions["bounded_html_references"] += overflow
        links = links[:limit]
    elif mime == "text/css":
        css = resource.body.decode("utf-8", errors="replace")
        # Bound the candidate length; leave dynamic imports and generated URLs offline.
        for match in re.finditer(r"""url\(\s*['"]?([^\s'")]{1,4096})['"]?\s*\)""", css, re.I):
            links.append(match[1])
            if len(links) >= MAX_ASSETS * 4:
                # The number beyond this cap is unknown; count bounded scans.
                omissions["bounded_css_scans"] += 1
                break
    result = []
    for link in links:
        try:
            result.append(validate_url(urljoin(base, link)))
        except (ValueError, SandboxError):
            omissions["invalid_or_prohibited_reference"] += 1
    return result


def capture(url: str) -> dict:
    events: list[dict] = []
    attempted: set[str] = set()
    omissions = Counter()
    budget = _TransferBudget(TRANSFER_LIMIT)
    deadline = time.monotonic() + CAPTURE_TIMEOUT - 2
    final_url, page = _fetch(url, origin=None, limit=RESOURCE_LIMIT, deadline=deadline,
                             budget=budget, events=events, attempted=attempted)
    mime = page.headers.get("content-type", "").lower().split(";")[0].strip()
    if mime not in {"text/html", "application/xhtml+xml"} or not 200 <= page.status < 300:
        raise SandboxError("Destination did not return an HTML document")
    parts = urlsplit(final_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    resources = {}
    used = 0

    def store(key: str, item: Captured) -> None:
        nonlocal used
        resources[key] = {"status": item.status, "headers": item.headers,
                          "body": base64.b64encode(item.body).decode("ascii")}
        used += len(item.body)

    store(final_url, page)
    pending = deque(_links(page, final_url, omissions))
    seen = {final_url}
    while (pending and len(seen) <= MAX_ASSETS and used < BUNDLE_LIMIT
           and budget.remaining > 0 and time.monotonic() < deadline):
        target = pending.popleft()
        if target in seen:
            continue
        seen.add(target)
        attempted.add(target)
        try:
            location, asset = _fetch(target, origin=origin, limit=min(RESOURCE_LIMIT, BUNDLE_LIMIT - used),
                                     deadline=deadline, budget=budget, events=events)
            if not 200 <= asset.status < 300:
                omissions["http_error"] += 1
                continue
            store(target, asset)
            if len(pending) < MAX_ASSETS * 4:
                pending.extend(_links(asset, location, omissions))
            else:
                omissions["bounded_discovery_scans"] += 1
        except SandboxError as error:
            omissions[str(error)] += 1
            _trace(events, url=target, destination_domain=urlsplit(target).hostname, blocked=True,
                   reason=str(error))
    remaining = len(set(pending) - seen)
    if remaining:
        omissions["pending_at_limit"] = remaining
    return {"url": final_url, "resources": resources, "broker_trace": events,
            "_capture_state": {"attempted_urls": sorted(attempted), "asset_attempts": len(seen) - 1, "rounds": 0},
            "capture": {"origin": origin, "resource_count": len(resources), "bytes": used,
                        "response_body_bytes_read": TRANSFER_LIMIT - budget.remaining,
                        "remaining_candidates": remaining, "omissions": dict(omissions),
                        "policy": "same-origin static GET replay"}}


def supplement_capture(captured: dict, candidates: list[dict]) -> dict:
    """Extend an archive with bounded same-origin dependencies observed in offline replay.

    The private state travels only between trusted supervisors and capture processes.
    Every approved URL still passes through the normal DNS-pinned HTTP capture path.
    """
    from .isolation import encode_replay_bundle

    try:
        encode_replay_bundle({"url": captured["url"], "resources": captured["resources"],
                              "mode": "javascript-analysis"})
        meta = captured["capture"]
        state = captured["_capture_state"]
        attempted_urls = state["attempted_urls"]
        attempts, rounds = state["asset_attempts"], state["rounds"]
        read_bytes = meta["response_body_bytes_read"]
        trace = captured["broker_trace"]
        if (not isinstance(candidates, list) or len(candidates) > MAX_SUPPLEMENT_CANDIDATES
                or not isinstance(attempted_urls, list) or len(attempted_urls) > MAX_ASSETS + MAX_REDIRECTS + 1
                or type(attempts) is not int or not 0 <= attempts <= MAX_ASSETS
                or type(rounds) is not int or not 0 <= rounds < MAX_SUPPLEMENT_ROUNDS
                or type(read_bytes) is not int or not 0 <= read_bytes <= TRANSFER_LIMIT
                or not isinstance(trace, list) or len(trace) > MAX_TRACE):
            raise ValueError("Invalid capture state")
        attempted = {validate_url(url) for url in attempted_urls}
        if len(attempted) != len(attempted_urls) or not set(captured["resources"]) <= attempted:
            raise ValueError("Invalid capture history")
        used = sum(len(base64.b64decode(item["body"], validate=True)) for item in captured["resources"].values())
        if used > read_bytes or len(captured["resources"]) - 1 > attempts:
            raise ValueError("Invalid capture accounting")
        omissions = Counter(meta["omissions"])
        if any(not isinstance(key, str) or type(value) is not int or value < 0
               for key, value in omissions.items()):
            raise ValueError("Invalid capture omissions")
    except Exception as error:
        raise SandboxError("Invalid supplemental capture input") from error

    root = urlsplit(captured["url"])
    origin = f"{root.scheme}://{root.netloc}"
    resources = dict(captured["resources"])
    events = list(trace)
    budget = _TransferBudget(TRANSFER_LIMIT - read_bytes)
    deadline = time.monotonic() + SUPPLEMENT_TIMEOUT - 1
    pending: deque[str] = deque()
    for item in candidates:
        if (not isinstance(item, dict) or item.get("resource_type") not in {"script", "stylesheet", "image", "font"}
                or item.get("method") != "GET" or item.get("navigation") is not False
                or set(item) != {"url", "resource_type", "method", "navigation"}):
            omissions["supplemental_request_declined"] += 1
            continue
        try:
            target = validate_url(item["url"])
            parts = urlsplit(target)
            if target != item["url"] or f"{parts.scheme}://{parts.netloc}" != origin:
                raise SandboxError("Cross-origin or noncanonical dependency")
        except (ValueError, SandboxError):
            omissions["supplemental_request_declined"] += 1
            continue
        pending.append(target)

    previous_count = len(resources)
    while pending and attempts < MAX_ASSETS and used < BUNDLE_LIMIT and budget.remaining > 0 and time.monotonic() < deadline:
        target = pending.popleft()
        if target in attempted:
            continue
        attempted.add(target)
        attempts += 1
        try:
            location, asset = _fetch(target, origin=origin, limit=min(RESOURCE_LIMIT, BUNDLE_LIMIT - used),
                                     deadline=deadline, budget=budget, events=events)
            if not 200 <= asset.status < 300:
                omissions["http_error"] += 1
                continue
            resources[target] = {"status": asset.status, "headers": asset.headers,
                                 "body": base64.b64encode(asset.body).decode("ascii")}
            used += len(asset.body)
            # The normal discovery path can recover CSS image and font dependencies.
            if len(pending) < MAX_ASSETS * 4:
                pending.extend(_links(asset, location, omissions))
            else:
                omissions["bounded_discovery_scans"] += 1
        except SandboxError as error:
            omissions[str(error)] += 1
            _trace(events, url=target, destination_domain=urlsplit(target).hostname, blocked=True, reason=str(error))
    remaining = len(set(pending) - attempted)
    if remaining:
        omissions["supplemental_pending_at_limit"] += remaining
    return {"url": captured["url"], "resources": resources, "broker_trace": events,
            "_capture_state": {"attempted_urls": sorted(attempted), "asset_attempts": attempts, "rounds": rounds + 1},
            "capture": {**meta, "origin": origin, "resource_count": len(resources), "bytes": used,
                        "response_body_bytes_read": TRANSFER_LIMIT - budget.remaining,
                        "remaining_candidates": meta.get("remaining_candidates", 0) + remaining,
                        "dynamic_resource_rounds": rounds + 1,
                        "dynamic_resources_added": meta.get("dynamic_resources_added", 0) + len(resources) - previous_count,
                        "omissions": dict(omissions)}}


def _main() -> None:
    # Separate process gives the controlling service a hard deadline even on stalled DNS.
    watchdog = threading.Timer(CAPTURE_TIMEOUT, os._exit, args=(124,))
    watchdog.daemon = True
    watchdog.start()
    try:
        payload = sys.stdin.buffer.read(CAPTURE_INPUT_LIMIT + 1)
        if len(payload) > CAPTURE_INPUT_LIMIT:
            raise SandboxError("Capture input exceeded its limit")
        request = json.loads(payload)
        if isinstance(request, dict) and set(request) == {"operation", "capture", "candidates"} and request["operation"] == "supplement":
            result = supplement_capture(request["capture"], request["candidates"])
        else:
            result = capture(validate_url(request))
        print(json.dumps(result, separators=(",", ":")))
    except SandboxError as error:
        print(json.dumps({"error": str(error), "timeout": isinstance(error, SandboxTimeout)}))
    except (UnicodeError, ValueError, RecursionError, AssertionError):
        print(json.dumps({"error": "Malformed capture input or document"}))
    finally:
        watchdog.cancel()


if __name__ == "__main__":
    _main()
