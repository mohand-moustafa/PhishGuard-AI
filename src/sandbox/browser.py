"""Bounded, offline Chromium analysis. The production entry point is worker.py."""

from __future__ import annotations

import base64
import io
import json
import math
import re
import secrets
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urlsplit

from PIL import Image, ImageChops, ImageDraw, ImageFilter
from playwright.sync_api import Browser, BrowserContext, Error, Frame, Page, Route
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from . import REPLAY_HEADERS


VIEWPORT = {"width": 1024, "height": 720}
MAX_REGIONS = 240
MAX_POINTS = 1800
MAX_ACTIONS = 4
MAX_SHADOW_ROOTS = 24
PASSIVE_INTERVAL_MS = 1100
RENDER_TIMEOUT_MS = 6000
RENDER_QUIET_MS = 450
FULL_PAGE_TIMEOUT_MS = 9000
FULL_PAGE_TILE_TIMEOUT_MS = 2200
FULL_PAGE_MAX_WIDTH = 1600
FULL_PAGE_MAX_HEIGHT = 8192
FULL_PAGE_MAX_PIXELS = 8_000_000
RENDER_RESOURCES = {"image", "script", "stylesheet", "font"}
SRC = Path(__file__).parent
READINESS = (SRC / "browser_readiness.js").read_text(encoding="utf-8")
SELECTORS = (SRC / "browser_selectors.js").read_text(encoding="utf-8")
MONITOR = "(() => {" + SELECTORS + (SRC / "browser_monitor.js").read_text(encoding="utf-8") + "})();"
INSPECT = """limits => {
    if (["chrome-error:", "chrome:", "devtools:"].includes(location.protocol)) return {internalDocument: true};
    let registered = [];
    try { registered = window.__phishguardRead?.("listeners") || []; } catch (_) {}
    const listeners = new Map(registered);
""" + SELECTORS + (SRC / "browser_inspect.js").read_text(encoding="utf-8") + "}"
PAINT = {"critical": "#a80738", "high": "#df343e", "medium": "#b16100",
         "low": "#26749c", "informational": "#667085"}


def display_url(value: Any) -> str:
    """Report the destination without disclosing URL credentials or query values."""
    try:
        parts = urlsplit(str(value)[:2000])
        if parts.scheme not in {"http", "https", "ws", "wss"}:
            return (parts.scheme + ":") if parts.scheme else ""
        netloc = parts.netloc.rsplit("@", 1)[-1]
        return f"{parts.scheme}://{netloc}{parts.path}"[:640]
    except ValueError:
        return ""


def domain(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_png(image: Image.Image, limit: int = 600_000) -> str:
    """Preserve viewport geometry for hit-testing even on noisy pages."""
    for colors in (256, 32, 8, 2):
        buf = io.BytesIO()
        image.convert("RGB").quantize(colors=colors).save(buf, format="PNG", optimize=False)
        if buf.tell() <= limit:
            return base64.b64encode(buf.getvalue()).decode("ascii")
    raise ValueError("Image exceeds bounded artifact budget")


def viewport_image(page: Page) -> Image.Image:
    raw = page.screenshot(type="png", timeout=3500, animations="allow", caret="hide")
    with Image.open(io.BytesIO(raw)) as image:
        return image.convert("RGB")


class JavaScriptBehaviorMonitor:
    def __init__(self, url: str, resources: dict[str, Any]):
        self.url = url
        self.resources = resources
        self.behavior: list[dict] = []
        self.network: list[dict] = []
        self.scripts: list[dict] = []
        self.script_keys: set[tuple] = set()
        self.script_chars = 0
        self.action_id: str | None = None
        self.element_id: str | None = None
        self.offline_action = False
        self.suppressed_navigations = 0
        self.prepaint_navigations = 0
        self.blocked_resources = Counter()
        self.scroll_blocked_requests = Counter()
        self.scroll_blocked_navigations = 0
        self.missing_resources: dict[str, dict] = {}
        self.replay = False
        self.phase = "baseline"
        self.sources: dict[tuple, str] = {}
        self.script_locations: dict[str, str] = {}
        self.dropped = Counter()
        self.marker = ""
        self.request_marks = defaultdict(deque)
        self.unmatched_routes = defaultdict(deque)
        self.session = "baseline"
        self.frame_keys: dict[Frame, str] = {}
        self.frame_generations: Counter = Counter()
        self.frame_serial = 0
        self.native_click: dict | None = None

    def frame_scope(self, frame: Frame) -> dict:
        key = self.frame_keys.get(frame)
        if not key:
            return {}
        generation = self.frame_generations[frame]
        result = {"frame_key": key, "frame_url": display_url(frame.url)}
        if generation:
            result["document_id"] = f"{self.session}:{key}@{generation}"
        return result

    def record(self, kind: str, provenance: str, fields: dict, *, network: bool = False) -> dict | None:
        # Only include initial baseline and action windows, not repeated passive replays.
        if self.phase == "full_page_scroll" or (self.replay and not self.action_id):
            return
        target = self.network if network else self.behavior
        if len(target) >= 1200:
            self.dropped[kind] += 1
            return
        data = {k: v[:1000] if isinstance(v, str) else v for k, v in fields.items()
                if isinstance(v, (str, bool, int, float)) and k not in {"code", "type", "action_id", "element_id", "provenance"}}
        if "url" in data:
            data["url"] = display_url(data["url"])
            data["domain"] = domain(data["url"])
        if self.marker:
            data = {k: v.replace(self.marker, "[synthetic]") if isinstance(v, str) else v for k, v in data.items()}
        record = {**data, "type": kind, "provenance": provenance,
                  "timestamp": data.get("timestamp") or utc_now(),
                  "observation_index": len(self.network) + len(self.behavior) + 1,
                  "action_id": self.action_id, "element_id": self.element_id, "trigger_phase": self.phase}
        target.append(record)
        return record

    def carries_marker(self, request: dict) -> bool:
        """Inspect a bounded CDP prefix for the generated password marker; retain only a boolean."""
        if not self.marker or not self.action_id:
            return False
        if self.marker in str(request.get("url", ""))[:8192]:
            return True
        if self.marker in str(request.get("postData", ""))[:65536]:
            return True
        data = bytearray()
        for entry in (request.get("postDataEntries") or [])[:8]:
            encoded = entry.get("bytes", "")[:87380]
            try:
                data.extend(base64.b64decode(encoded)[:65536 - len(data)])
            except ValueError:
                continue
            if len(data) == 65536:
                break
        return self.marker.encode("ascii") in data

    def add_script(self, item: dict) -> None:
        if self.phase == "full_page_scroll" or (self.replay and not self.action_id):
            return
        if str(item.get("source", "")).startswith(("chrome-error:", "chrome:", "devtools:")):
            return
        key = (item.get("document_id"), item.get("source"), item.get("selector"), item.get("event"),
               item.get("code", "")[:64000])
        if key in self.script_keys or len(self.scripts) >= 128 or self.script_chars >= 220_000:
            return
        self.script_keys.add(key)
        code = str(item.get("code", ""))[:min(64000, 220000 - self.script_chars)]
        self.scripts.append({"source": display_url(item.get("source")), "code": code,
                             "selector": str(item.get("selector", ""))[:800], "kind": item.get("kind"),
                             "event": item.get("event"), "action_id": self.action_id,
                             **{k:item[k] for k in ("frame_key","document_id","frame_url") if k in item}})
        self.script_chars += len(code)

    def route(self, route: Route) -> None:
        request = route.request
        key = urldefrag(request.url).url
        resource = self.resources.get(key)
        allowed = not self.offline_action and request.method == "GET" and resource is not None
        if not allowed and not self.replay:
            kind = request.resource_type
            parts, original = urlsplit(key), urlsplit(self.url)
            if (resource is None and not self.action_id and not self.offline_action
                    and request.method == "GET" and not request.is_navigation_request()
                    and kind in RENDER_RESOURCES and len(key) <= 4096
                    and (parts.scheme, parts.netloc) == (original.scheme, original.netloc)
                    and len(self.missing_resources) < 12):
                self.missing_resources.setdefault(key, {
                    "url": key, "method": "GET", "navigation": False, "resource_type": kind})
            if self.phase == "full_page_scroll":
                self.scroll_blocked_requests[kind] += 1
                if request.is_navigation_request():
                    self.scroll_blocked_navigations += 1
            elif kind in RENDER_RESOURCES:
                self.blocked_resources[kind] += 1
        try:
            frame = request.frame
            scope = self.frame_scope(frame)
        except Error:
            frame = None
            scope = {}
        # Aborting a top-level navigation can replace the last captured page with
        # Chromium's network error document. A local 204 retains the committed page.
        archive_navigation = (not allowed and resource is None and not self.replay and not self.offline_action
                              and request.method == "GET" and request.is_navigation_request()
                              and scope.get("frame_key") == "main" and bool(scope.get("document_id"))
                              and frame is not None and urldefrag(frame.url).url in self.resources)
        record = self.record("request", "playwright", {**scope, "url": key, "blocked": not allowed, "method": request.method,
                    "resource_type": request.resource_type, "navigation": request.is_navigation_request(),
                    "initiator": self.sources.get((scope.get("document_id"),key), "") if scope.get("document_id") else "",
                    "outcome": "cache_replay" if allowed else "blocked"},
                    network=True)
        if record and self.action_id:
            identifier = (scope.get("document_id"), request.method, key)
            record["synthetic_credential"] = self.carries_marker({"url": key})
            if self.request_marks.get(identifier):
                record["synthetic_credential"] |= self.request_marks[identifier].popleft()
            elif scope.get("document_id"):
                self.unmatched_routes[identifier].append(record)
        if not allowed:
            if archive_navigation and self.main_painted:
                route.fulfill(status=204, headers={"Cache-Control": "no-store"})
                self.suppressed_navigations += 1
                if record:
                    record["navigation_suppressed"] = True
            else:
                if archive_navigation:
                    # Retaining an unpainted document interrupted inside its parser can
                    # leave Chromium without a compositor frame to capture.
                    self.prepaint_navigations += 1
                    if record:
                        record["navigation_before_paint"] = True
                route.abort("blockedbyclient")
            return
        headers = resource.get("headers", {})
        body = base64.b64decode(resource["body"], validate=True)
        if request.resource_type == "script":
            self.add_script({**scope, "source": key, "kind": "external", "code": body[:64000].decode("utf-8", "replace")})
        # Fetcher supplies fully decoded bodies. Never replay credentials, cookies,
        # response redirects, authentication challenges, or client hint requests.
        headers = {k.lower(): str(v) for k, v in headers.items() if k.lower() in REPLAY_HEADERS}
        route.fulfill(status=resource.get("status", 200), headers=headers, body=body)

    def attach(self, context: BrowserContext, page: Page) -> None:
        self.frame_keys = {page.main_frame: "main"}
        self.frame_generations.clear()
        self.frame_serial = 0
        def attached(frame: Frame):
            parent = self.frame_keys.get(frame.parent_frame)
            if parent and self.frame_serial < 96:
                self.frame_serial += 1
                self.frame_keys[frame] = f"{parent}/frame-{self.frame_serial}"
        def navigated(frame: Frame):
            if frame in self.frame_keys:
                previous = self.frame_scope(frame).get("document_id")
                self.frame_generations[frame] += 1
                self.record("frame_navigation", "playwright", {**self.frame_scope(frame),
                            "previous_document_id": previous, "url": frame.url})
        page.on("frameattached", attached)
        page.on("framenavigated", navigated)
        context.route("**/*", self.route)
        def block_socket(ws):
            self.record("websocket", "playwright", {"url": ws.url, "blocked": True}, network=True)
            ws.close()
        context.route_web_socket("**/*", block_socket)
        context.add_init_script(script=MONITOR)
        page.on("download", lambda dl: self.record("download", "playwright", {"url": dl.url, "blocked": True}))
        def close_popup(popup: Page):
            self.record("popup", "playwright", {"url": popup.url, "blocked": True})
            popup.close()
        context.on("page", close_popup)
        page.on("dialog", lambda dialog: dialog.dismiss())
        cdp = context.new_cdp_session(page)
        self.cdp = cdp
        main_id = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
        self.main_painted = False
        main_loader = None
        def document_committed(event):
            nonlocal main_loader
            frame = event["frame"]
            if frame["id"] == main_id:
                main_loader = frame["loaderId"]
                self.main_painted = False
        def paint_observed(event):
            if (event["frameId"] == main_id and event["loaderId"] == main_loader
                    and event["name"] in {"firstPaint", "firstContentfulPaint"}):
                self.main_painted = True
        cdp.on("Page.frameNavigated", document_committed)
        cdp.on("Page.lifecycleEvent", paint_observed)
        def cdp_scope(frame_id):
            return self.frame_scope(page.main_frame) if frame_id == main_id else {}
        contexts = {}
        def remember_context(event):
            ctx = event["context"]
            if len(contexts) < 256:
                contexts[ctx["id"]] = ctx.get("auxData", {}).get("frameId")
        cdp.on("Runtime.executionContextCreated", remember_context)
        self.sources.clear()
        self.script_locations.clear()
        def request_sent(event):
            req = event.get("request", {})
            url = req.get("url", "")
            scope = cdp_scope(event.get("frameId"))
            document_id = scope.get("document_id")
            initiator = event.get("initiator", {})
            frames = initiator.get("stack", {}).get("callFrames", [])
            if document_id and len(self.sources) < 600:
                self.sources[(document_id,url)] = display_url(frames[0].get("url") if frames else initiator.get("url"))
            if self.action_id and document_id:
                key = (document_id, req.get("method"), urldefrag(url).url)
                mark = self.carries_marker(req)
                if self.unmatched_routes.get(key):
                    record = self.unmatched_routes[key].popleft()
                    record["synthetic_credential"] |= mark
                    record["initiator"] = self.sources.get((document_id,url), "")
                elif len(self.request_marks) < 1200 and len(self.request_marks[key]) < 32:
                    self.request_marks[key].append(mark)
            if event.get("redirectResponse"):
                self.record("redirect", "cdp", {**scope, "url": url, "from_url": display_url(event["redirectResponse"].get("url"))})
        cdp.on("Network.requestWillBeSent", request_sent)
        cdp.on("Page.frameRequestedNavigation", lambda e: self.record("redirect", "cdp",
            {**cdp_scope(e.get("frameId")), "url": e.get("url"), "reason": e.get("reason"), "navigation_intent": True}))
        def parsed(event):
            location = event.get("url", "")
            if location.startswith(("http://", "https://")):
                if len(self.script_locations) < 512:
                    self.script_locations[event["scriptId"]] = display_url(location)
                self.record("script_parsed", "cdp", {**cdp_scope(contexts.get(event.get("executionContextId"))),
                            "url": location, "line": event.get("startLine", 0) + 1})
        cdp.on("Debugger.scriptParsed", parsed)
        cdp.send("Network.enable", {"maxPostDataSize": 65536})
        for method in ["Page.enable", "Runtime.enable", "Debugger.enable"]:
            cdp.send(method)
        cdp.send("Page.setLifecycleEventsEnabled", {"enabled": True})
        cdp.send("Debugger.setSkipAllPauses", {"skip": True})
        cdp.send("Page.setDownloadBehavior", {"behavior": "deny"})

    def drain(self, page: Page) -> None:
        for frame in page.frames[:12]:
            if frame.url.startswith(("chrome-error:", "chrome:", "devtools:")):
                continue
            scope = self.frame_scope(frame)
            try:
                # Some Chromium builds retain the failed HTTP URL on Frame.url while
                # location.href reflects the internal network error document.
                events = frame.evaluate("""() => ["chrome-error:","chrome:","devtools:"].includes(location.protocol)
                    ? [] : (window.__phishguardRead?.("events") || [])""")
            except Error:
                continue
            if not isinstance(events, list) or self.frame_scope(frame) != scope:
                continue
            for event in events[:300]:
                if not isinstance(event, dict):
                    continue
                kind = str(event.get("type", ""))[:48]
                event = {k:v for k,v in event.items() if k not in {"frame_key","document_id","frame_url"}}
                if (kind == "click" and event.get("trusted") and self.native_click and
                        self.native_click["selector"] == event.get("selector") and
                        self.native_click.get("document_id") == scope.get("document_id")):
                    self.native_click["document_sequence"] = event.get("document_sequence")
                    self.native_click["corroborated_by"] = "instrumentation"
                    continue
                self.record(kind, "instrumentation", {**event, **scope})
                if kind == "script_inserted" and event.get("code"):
                    self.add_script({"source": frame.url, "code": event["code"], "selector": event.get("selector"),
                                     "kind": "dynamic", **scope})

    def document_value(self, expression: str, *, timeout_ms: int = 3000) -> Any:
        """Inspect the primary document with Chromium's untampered JS prototypes."""
        tree = self.cdp.send("Page.getFrameTree")
        world = self.cdp.send("Page.createIsolatedWorld", {"frameId": tree["frameTree"]["frame"]["id"],
                                                           "worldName": "phishguard-inspector"})
        self.world = world["executionContextId"]
        result = self.cdp.send("Runtime.evaluate", {"expression": expression,
                               "contextId": self.world, "returnByValue": True, "timeout": timeout_ms})
        if "exceptionDetails" in result or "value" not in result["result"]:
            raise Error("Chrome DOM inspection failed")
        return result["result"]["value"]

    def viewport_capture(self, clip: dict | None = None) -> Image.Image:
        """Capture the compositor surface even when document fonts are still pending."""
        params = {"format": "png", "captureBeyondViewport": False}
        if clip is not None:
            params["clip"] = clip
        raw = self.cdp.send("Page.captureScreenshot", params)
        with Image.open(io.BytesIO(base64.b64decode(raw["data"]))) as image:
            return image.convert("RGB")

    def arm_click_observer(self, target_doc: dict) -> None:
        """Retain a trusted native click across unload without exposing a page-world binding."""
        frame_id = self.cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
        realm = self.cdp.send("Page.createIsolatedWorld", {"frameId":frame_id, "worldName":"phishguard-pointer"})
        context_id = realm["executionContextId"]
        binding = "__phishguardNativePointer"
        self.cdp.send("Runtime.addBinding", {"name":binding, "executionContextId":context_id})
        def received(event):
            if (event.get("executionContextId") != context_id or event.get("name") != binding
                    or self.phase != "click" or self.native_click is not None):
                return
            self.native_click = self.record("click", "cdp", {**target_doc, "trusted":True,
                                            "selector":str(event["payload"])[:800]})
        self.cdp.on("Runtime.bindingCalled", received)
        expression = "(() => {" + SELECTORS + """
            function capture(event) {
                if (!event.isTrusted) return;
                window.removeEventListener("click", capture, true);
                window.__phishguardNativePointer(selector(event.composedPath()[0] || event.target));
            }
            window.addEventListener("click", capture, true);
        })()"""
        result = self.cdp.send("Runtime.evaluate", {"contextId":context_id, "expression":expression,"timeout":500})
        if "exceptionDetails" in result:
            raise Error("Could not establish pointer observation")

    def inspect_frame(self, frame: Frame, limits: dict) -> dict:
        if frame.parent_frame:
            return frame.evaluate(INSPECT, limits)
        listeners = frame.evaluate('() => window.__phishguardRead?.("listeners") || []')
        safe_listeners = []
        for entry in listeners[:350] if isinstance(listeners, list) else []:
            if isinstance(entry, list) and len(entry) == 2 and isinstance(entry[1], list):
                safe_listeners.append([str(entry[0])[:800], [str(x)[:24] for x in entry[1][:8]]])
        invocation = INSPECT.replace('window.__phishguardRead?.("listeners") || []', 'limits.listeners')
        expression = "(" + invocation + ")(" + json.dumps({**limits, "listeners": safe_listeners}) + ")"
        return self.document_value(expression)

    def inspect_handlers(self, regions: list[dict]) -> None:
        """Resolve browser-known handler locations for up to 16 priority targets."""
        candidates = sorted((r for r in regions if not r["frame"] and not r.get("shadow_path") and (r["interactive"] or r["intercepts"])),
                            key=lambda r: (bool(r["intercepts"]), bool(r["handlers"]), r["hidden"]), reverse=True)
        try:
            for row in candidates[:16]:
                obj = self.cdp.send("Runtime.evaluate", {
                    "contextId": self.world, "objectGroup": "handler-inspection",
                    "expression": "document.querySelector(" + json.dumps(row["selector"]) + ")",
                    "timeout": 250})["result"]
                if not obj.get("objectId"):
                    continue
                details = self.cdp.send("DOMDebugger.getEventListeners", {"objectId": obj["objectId"], "depth": 1})
                row["handler_locations"] = [{"event": item["type"], "source": self.script_locations.get(item["scriptId"], ""),
                                             "line": item["lineNumber"] + 1, "column": item["columnNumber"] + 1,
                                             "frame_key":row["frame_key"],"document_id":row["document_id"]}
                                            for item in details["listeners"][:12]]
                row["handlers"] = list(dict.fromkeys([*row["handlers"], *(h["event"] for h in row["handler_locations"])]))
        except Error:
            # Page may have navigated between the passive snapshot and the handler audit.
            return
        finally:
            self.cdp.send("Runtime.releaseObjectGroup", {"objectGroup": "handler-inspection"})


class InvisibleInteractionDetector:
    """A low-opacity CSS value has no evidentiary weight without its hit-test context."""

    @staticmethod
    def classify(region: dict, image: Image.Image) -> None:
        box = region["bbox"]
        sample = region.get("visual_evidence_bbox") or box
        bounds = (max(0, int(sample["x"])), max(0, int(sample["y"])),
                  min(image.width, int(sample["x"] + sample["width"])), min(image.height, int(sample["y"] + sample["height"])))
        contrast, edges = 0, 0.0
        if bounds[2] > bounds[0] and bounds[3] > bounds[1]:
            crop = image.crop(bounds).convert("L")
            crop.thumbnail((180, 140))
            low, high = crop.getextrema()
            contrast = high - low
            if min(crop.size) > 3:
                edge = crop.filter(ImageFilter.FIND_EDGES).crop((1, 1, crop.width - 1, crop.height - 1))
                edges = round(sum(edge.histogram()[26:]) / (edge.width * edge.height), 3)
        region["pixels"] = {"contrast": contrast, "edge_density": edges}
        region["visual_mismatch"] = bool(region.get("visual_evidence_bbox") and region["hidden"] and contrast >= 24 and edges > 0.001)
        evidence: list[str] = []
        severity, confidence, category = "informational", 0.7, "visible_control"
        if region["hidden"]:
            evidence.append("Low rendered opacity or non-visible styling." if not region["empty_layer"]
                            else "Positioned layer has no visible content, border or fill.")
        if region["offscreen"]:
            evidence.append("Bounding rectangle does not intersect the viewport.")
        if region["covers_viewport"] and region["hidden"]:
            evidence.append("The hidden layer spans at least 90 percent of the viewport.")
        if 0 < min(box["width"], box["height"]) < 4:
            evidence.append("Clickable rectangle has a dimension below four CSS pixels.")
        if region["css"]["zIndex"].lstrip("-").isdigit() and int(region["css"]["zIndex"]) >= 1000:
            evidence.append("Elevated stacking order.")
        if region["intercepts"]:
            evidence.append("Coordinate testing found a distinct control with visible styling underneath the receiver.")
        if region["visual_mismatch"]:
            evidence.append("Viewport pixels contain visible structure inside the invisible receiver's bounds.")
        if region["accessibility"] and not region["intercepts"]:
            category = "accessibility_control"
        elif region["hidden"] and not region["receives_pointer"]:
            category = "non_receiving_hidden_element"
        elif region["hidden"] and region["intercepts"]:
            category, severity, confidence = "suspicious_interception", "high", 0.86 if region["visual_mismatch"] else 0.75
        elif region["hidden"] and region["interactive"] and region["receives_pointer"]:
            category, severity, confidence = "invisible_receiver", "medium", 0.66
        elif region["hidden"]:
            category = "transparent_layout"
        elif region.get("destination_mismatch"):
            category, severity, confidence = "destination_mismatch", "medium", 0.76
            evidence.append("The displayed URL or underlying control names a different destination host.")
        elif region["intercepts"] and region["interactive"]:
            category, severity, confidence = "overlapping_controls", "low", 0.62
        elif region["covered_by"]:
            category, severity, confidence = "covered_control", "low", 0.64
            evidence.append("A different element received the pointer at a sampled coordinate.")
        elif region["offscreen"]:
            category = "outside_viewport"
        elif region["interactive"] and 0 < min(box["width"], box["height"]) < 4:
            category, severity, confidence = "tiny_control", "low", 0.5
        if region["tag"] == "form" and region["credential"] and region["hidden"] and region["destination"] and (
            domain(region["destination"]) != domain(region["frame_url"])
        ):
            category, severity, confidence = "hidden_credential_form", "medium", 0.7
            evidence.append("Hidden form contains a password input and names an external destination.")
        region.update(classification=category, severity=severity, confidence=confidence, evidence=evidence,
                      explanation=" ".join(evidence) or "Visible region with no observed interception.")


class VisualInteractionScanner:
    def __init__(self, monitor: JavaScriptBehaviorMonitor):
        self.monitor = monitor
        self.frame_nodes: Counter = Counter()
        self.region_visits = 0
        self.shadow_visits = 0
        self.shadow_hosts = set()
        self.complete_documents = {"early": set(), "late": set()}
        self.coverage = {"frames_scanned": 0, "nodes_scanned": 0, "candidates": 0, "samples": 0,
                         "open_shadow_roots": 0, "shadow_truncated": False, "truncated": False, "warnings": []}

    def project_frame(self, frame: Frame, rows: list[dict]) -> bool:
        """Map nested frame CSS pixels to the screenshot, testing each parent hit surface."""
        while frame.parent_frame:
            points = [p for row in rows for p in row["points"]]
            handle = frame.frame_element()
            try:
                geom = handle.evaluate("(el,points) => {" + SELECTORS + """
                    const box = el.getBoundingClientRect();
                    if (!el.offsetWidth || !el.offsetHeight) return null;
                    let opacity = 1;
                    for (let n=el;n;n=composedParent(n)) {
                        const css = getComputedStyle(n);
                        opacity *= Number(css.opacity);
                        if (css.transform === "none") continue;
                        const matrix = new DOMMatrixReadOnly(css.transform);
                        if (!matrix.is2D || matrix.b || matrix.c || matrix.a<=0 || matrix.d<=0) return null;
                    }
                    const sx=box.width/el.offsetWidth, sy=box.height/el.offsetHeight;
                    const dx=box.x+el.clientLeft*sx, dy=box.y+el.clientTop*sy;
                    const hits=points.map(([x,y]) => hitStack(dx+x*sx,dy+y*sy).hit===el);
                    return {sx,sy,dx,dy,opacity,hits,width:innerWidth,height:innerHeight};
                }""", [[p["x"], p["y"]] for p in points])
            finally:
                handle.dispose()
            if not geom:
                return False
            for p, exposed in zip(points, geom["hits"]):
                p["x"] = geom["dx"] + p["x"] * geom["sx"]
                p["y"] = geom["dy"] + p["y"] * geom["sy"]
                if not exposed:
                    p.update(receives=False, covered=False, expected="", hit="", receiver="", stack=[],
                             blocked_at_frame_boundary=True)
            for row in rows:
                b = row["bbox"]
                b.update(x=geom["dx"]+b["x"]*geom["sx"], y=geom["dy"]+b["y"]*geom["sy"],
                         width=b["width"]*geom["sx"], height=b["height"]*geom["sy"])
                row["effective_opacity"] *= geom["opacity"]
                row["hidden"] |= row["effective_opacity"] <= 0.1
                row["offscreen"] |= (b["x"] >= geom["width"] or b["y"] >= geom["height"] or
                                     b["x"] + b["width"] <= 0 or b["y"] + b["height"] <= 0)
            frame = frame.parent_frame
        return True

    def scan(self, page: Page, screenshot: Image.Image, *, early: bool = False) -> list[dict]:
        regions: list[dict] = []
        stage = "early" if early else "late"
        if len(page.frames) > 12:
            self.coverage["truncated"] = True
        for index, frame in enumerate(page.frames[:12]):
            remaining = (40 if early else MAX_REGIONS) - self.region_visits
            if remaining <= 0 or (frame not in self.frame_nodes and len(self.frame_nodes) >= 12):
                self.coverage["truncated"] = True
                break
            scope = self.monitor.frame_scope(frame)
            if not scope.get("document_id"):
                self.coverage["warnings"].append("Skipped frame with unverified document identity.")
                continue
            try:
                limits = {"nodes": max(0,(400 if early else 2500) - self.frame_nodes[frame]), "regions": remaining,
                          "shadows": max(0,(6 if early else MAX_SHADOW_ROOTS) - self.shadow_visits),
                          "points": max(0,(240 if early else MAX_POINTS) - self.coverage["samples"])}
                data = self.monitor.inspect_frame(frame, limits)
                if data.get("internalDocument"):
                    warning = "Chromium displayed an internal document. Its controls were excluded from analysis."
                    if warning not in self.coverage["warnings"]:
                        self.coverage["warnings"].append(warning)
                    continue
                self.frame_nodes[frame] += data["nodes"]
                self.region_visits += len(data["regions"])
                self.shadow_visits += data["shadowRoots"]
                self.shadow_hosts.update((scope["document_id"], host) for host in data["shadowHosts"])
                self.coverage["open_shadow_roots"] = len(self.shadow_hosts)
                self.coverage["shadow_truncated"] |= data["shadowTruncated"]
                self.coverage["frames_scanned"] = len(self.frame_nodes)
                self.coverage["nodes_scanned"] += data["nodes"]
                self.coverage["candidates"] += data["candidates"]
                self.coverage["samples"] += data["sampleCount"]
                self.coverage["truncated"] |= (data["node_limit"] or data["shadowTruncated"] or
                                              data["candidates"] > len(data["regions"]))
                if not self.project_frame(frame, data["regions"]):
                    self.coverage["warnings"].append("Skipped frame with non-axis-aligned or empty geometry.")
                    continue
                if scope != self.monitor.frame_scope(frame):
                    self.coverage["warnings"].append("Frame navigated during inspection.")
                    continue
                if (not data["node_limit"] and not data["shadowTruncated"] and
                        data["candidates"] == len(data["regions"]) and data["sampleCount"] < limits["points"]):
                    self.complete_documents[stage].add(scope["document_id"])
            except Error:
                self.coverage["warnings"].append("Frame detached or unavailable during inspection.")
                continue
            for script in data["scripts"]:
                self.monitor.add_script({**script, **scope})
            for row in data["regions"]:
                for field in ("tag", "input_type", "role", "destination", "frame_key", "selector"):
                    val = row.get(field)
                    if not isinstance(val, str):
                        row[field] = "" if val is None or isinstance(val, (dict, list)) else str(val)
                row.update(scope)
                row.update(id=f"region-{len(regions)+1}", frame=index,
                           destination=display_url(row["destination"]), intercepts=[], covered_by=[])
                regions.append(row)

        self.coverage["truncated"] |= self.coverage["samples"] >= MAX_POINTS
        by_selector = {(r["frame"], r["selector"]): r for r in regions}
        for row in regions:
            points = row["points"]
            row["actual_receiver"] = points[0]["receiver"] if points else ""
            row["receives_pointer"] = any(p["receives"] for p in points)
        for row in regions:
            points = row["points"]
            for p in points:
                if p["receives"] and p["expected"] and p["expected"] not in row["intercepts"]:
                    row["intercepts"].append(p["expected"])
                    row.setdefault("interception_point", {"x": p["x"], "y": p["y"], "hit": p["hit"]})
                if not p["covered"] or p["receiver"] in row["covered_by"]:
                    continue
                row["covered_by"].append(p["receiver"])
                covering = by_selector.get((row["frame"], p["hit"])) or by_selector.get((row["frame"], p["owner"]))
                if covering and covering is not row and not row["hidden"]:
                    if row["selector"] not in covering["intercepts"]:
                        covering["intercepts"].append(row["selector"])
                    covering["receives_pointer"] = True
                    covering.setdefault("interception_point", {"x": p["x"], "y": p["y"], "hit": p["hit"]})
        for row in regions:
            row["expected_target"] = next(iter(row["intercepts"]), row["selector"])
            expected = by_selector.get((row["frame"], row["expected_target"]), {})
            if row["intercepts"] and expected:
                a, b = row["bbox"], expected["bbox"]
                x, y = max(a["x"], b["x"]), max(a["y"], b["y"])
                w = min(a["x"]+a["width"], b["x"]+b["width"]) - x
                h = min(a["y"]+a["height"], b["y"]+b["height"]) - y
                if w > 0 and h > 0:
                    row["visual_evidence_bbox"] = {"x": x, "y": y, "width": w, "height": h}
            label = row["visible_text"]
            label_url = label if row["tag"] == "a" and re.fullmatch(r"https?://[^\s]+", label, re.I) else ""
            row["expected_destination"] = display_url(label_url) or expected.get("destination", "")
            row["destination_mismatch"] = bool(domain(row["destination"]) and
                domain(row["expected_destination"]) and domain(row["expected_destination"]) != domain(row["destination"]))
            InvisibleInteractionDetector.classify(row, screenshot)
        if not early:
            self.monitor.inspect_handlers(regions)
        return regions


def compare_checkpoints(early: list[dict], late: list[dict], *, early_complete: set, late_complete: set) -> tuple[list[dict], bool]:
    """Only compare hits at identical coordinates in a uniquely identified document and root."""
    def index_selectors(rows):
        found = {}
        for row in rows:
            key = (row["document_id"], row["selector"])
            found[key] = None if key in found else row
        return found
    previous, current = index_selectors(early), index_selectors(late)
    changes = []
    limited = False
    def change(kind, row, old=None, new=None, point=None):
        nonlocal limited
        if len(changes) >= 64:
            limited = True
            return
        changes.append({"type": kind, "selector": row["selector"], "frame_key": row["frame_key"],
                        "document_id": row["document_id"], "region_id": row["id"] if kind != "last_seen_early" else None,
                        "before_receiver": old, "after_receiver": new,
                        "x": point["x"] if point else None, "y": point["y"] if point else None})
    for row in late:
        row["passive_only"] = True
        row["probe_exclusion"] = "ambiguous-selector"
    for key, row in current.items():
        if row is None or (key in previous and previous[key] is None):
            continue
        old = previous.get(key)
        if not old:
            if row["document_id"] in early_complete:
                change("first_seen_late", row, new=row["actual_receiver"])
                row["probe_exclusion"] = "first-observed-late"
            else:
                pick = row.get("interception_point") or next((p for p in row.get("points", []) if p["receives"]), None)
                if not row.get("frame") and not row.get("shadow_path") and pick and " >>> " not in pick["hit"]:
                    row["probe_verification"] = "early-replay-required"
                    row["probe_exclusion"] = None
                    row["passive_only"] = False
                else:
                    row["probe_exclusion"] = "incomplete-early-map"
            continue
        at = {(p["x"],p["y"]):p["hit"] for p in old["points"]}
        pick = row.get("interception_point") or next((p for p in row["points"] if p["receives"]), None)
        row["probe_exclusion"] = "no-repeatable-hit"
        if row["frame"]:
            row["probe_exclusion"] = "child-frame"
        elif row["shadow_path"] or (pick and " >>> " in pick["hit"]):
            row["probe_exclusion"] = "shadow-root"
        elif pick:
            row["passive_only"] = at.get((pick["x"],pick["y"])) != pick["hit"]
            if not row["passive_only"]:
                row["probe_exclusion"] = None
        for p in row["points"]:
            old_hit = at.get((p["x"],p["y"]))
            if old_hit and p["hit"] and old_hit != p["hit"]:
                change("receiver_changed", row, old_hit, p["hit"], p)
                break
    for key, row in previous.items():
        if row is not None and key not in current and row["document_id"] in late_complete:
            change("last_seen_early", row, old=row["actual_receiver"])
    return changes, limited


class SafeInteractionEngine:
    """Rebuild baseline in a new context for each bounded offline experiment."""

    dangerous = re.compile(r"\b(pay|payment|purchase|buy|checkout|delete|remove|unsubscribe|"
                           r"confirm order|transfer|withdraw|place order|donate|upload)\b", re.I)

    def __init__(self, browser: Browser, url: str, resources: dict[str, Any]):
        self.browser, self.url = browser, url
        self.monitor = JavaScriptBehaviorMonitor(url, resources)
        self.screenshots: dict[str, str] = {}

    def open_replay(self, wait_ms: float = 350) -> tuple[BrowserContext, Page]:
        context = self.browser.new_context(viewport=VIEWPORT, screen=VIEWPORT, device_scale_factor=1,
                    locale="en-US", timezone_id="UTC", accept_downloads=False,
                    service_workers="block", permissions=[], reduced_motion="reduce")
        try:
            page = context.new_page()
            page.set_default_timeout(1800)
            self.monitor.attach(context, page)
            self.monitor.offline_action = False
            if self.monitor.replay:
                page.goto(self.url, wait_until="domcontentloaded", timeout=6000)
            else:
                page.goto(self.url, wait_until="commit", timeout=6000)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=1200)
                except PlaywrightTimeoutError:
                    # An inline navigation may interrupt the original load events.
                    # Only continue investigating a committed, archived document.
                    scope = self.monitor.frame_scope(page.main_frame)
                    if not scope.get("document_id") or urldefrag(page.url).url not in self.monitor.resources:
                        raise
            self.loaded_at = time.monotonic()
            page.wait_for_timeout(wait_ms)
            return context, page
        except BaseException:
            context.close()
            raise

    def wait_for_render(self, page: Page, earliest: float, *, timeout_ms: int = RENDER_TIMEOUT_MS,
                        allow_empty_tile: bool = False) -> dict:
        """Wait for observable viewport readiness within the passive replay budget."""
        started = time.monotonic()
        deadline = started + timeout_ms / 1000
        stable_since = None
        previous_pixels = None
        previous_state = None
        state = {}
        while True:
            waiting = []
            limitations = []
            try:
                remaining_ms = max(1, round((deadline - time.monotonic()) * 1000))
                state = self.monitor.document_value(READINESS, timeout_ms=min(500, remaining_ms))
                clip = {"x": state["scroll_x"], "y": state["scroll_y"], **VIEWPORT, "scale": 0.25}
                pixels = self.monitor.viewport_capture(clip)
                state["visible_content"] = any(hi - lo > 3 for lo, hi in pixels.getextrema())
                now = time.monotonic()
                same = (state == previous_state and previous_pixels is not None and
                        pixels.size == previous_pixels.size and
                        all(hi <= 8 for _, hi in ImageChops.difference(pixels, previous_pixels).getextrema()))
                if not same:
                    stable_since = now
                previous_pixels, previous_state = pixels, state
                if not state["document_complete"]:
                    waiting.append("document_loading")
                if not state["visible_content"] and not allow_empty_tile:
                    waiting.append("no_visible_content")
                waiting.extend(key for key in ("fonts_loading", "pending_images", "busy_components") if state[key])
                if (now - stable_since) * 1000 < RENDER_QUIET_MS:
                    waiting.append("viewport_changing")
                limitations.extend(key for key in ("failed_images", "inspection_limited", "browser_error_document")
                                   if state[key])
            except Error:
                # The document can be replaced during the sample. Retry within the same deadline.
                previous_pixels, previous_state = None, None
                state = {}
                waiting.append("inspection_unavailable")
            if self.monitor.suppressed_navigations:
                limitations.append("navigation_suppressed")
            if self.monitor.prepaint_navigations:
                limitations.append("navigation_before_paint")
            if self.monitor.blocked_resources:
                limitations.append("blocked_resources")
            now = time.monotonic()
            # Once the offline navigation has committed Chromium's error document,
            # there is no target page left that could finish loading components.
            blocked_error_page = state.get("browser_error_document") and self.monitor.prepaint_navigations > 0
            if now >= earliest and (blocked_error_page or not waiting):
                status = "partial" if limitations else "ready"
                break
            if now >= deadline:
                status = "timed_out"
                break
            page.wait_for_timeout(min(200, (deadline - now) * 1000))
        return {**state, "status": status, "waited_ms": round((now - started) * 1000),
                "timeout_ms": timeout_ms, "blocked_resources": dict(self.monitor.blocked_resources),
                "suppressed_navigations": self.monitor.suppressed_navigations,
                "prepaint_navigations": self.monitor.prepaint_navigations,
                "reasons": waiting + limitations}

    def capture_full_page(self, page: Page, initial: Image.Image, readiness: dict) -> dict:
        """Capture consecutive, settled viewport slices. Scroll events stay outside the baseline trace."""
        started = time.monotonic()
        deadline = started + FULL_PAGE_TIMEOUT_MS / 1000
        monitor = self.monitor

        def document_size() -> tuple[int, int]:
            size = monitor.cdp.send("Page.getLayoutMetrics")["cssContentSize"]
            return max(1, math.ceil(size["width"])), max(1, math.ceil(size["height"]))

        reasons = set(readiness["reasons"])
        extent_known = True
        try:
            width, height = document_size()
        except Error:
            width, height = initial.size
            extent_known = False
            reasons.update(("inspection_unavailable", "viewport_fallback"))
        stitched_width = min(width, FULL_PAGE_MAX_WIDTH)
        height_limit = min(FULL_PAGE_MAX_HEIGHT, FULL_PAGE_MAX_PIXELS // stitched_width)
        summary = {"visited_viewports": 1, "method": "viewport", "timeout_ms": FULL_PAGE_TIMEOUT_MS,
                   "max_pending_images": readiness.get("pending_images", 0),
                   "max_failed_images": readiness.get("failed_images", 0)}
        rows = []
        covered_height = 0
        complete = width <= initial.width and height <= initial.height
        monitor.phase = "full_page_scroll"
        try:
            while not complete and not readiness.get("browser_error_document"):
                if time.monotonic() >= deadline:
                    reasons.add("scan_budget")
                    break
                # Overlap successive views so short sticky headers don't obscure the seam.
                y = max(0, covered_height - 80)
                row = None
                row_height = min(initial.height, height_limit - covered_height)
                covered_width = 0
                while covered_width < stitched_width:
                    x = max(0, covered_width - 48)
                    if not rows and covered_width == 0 and readiness.get("scroll_x") == 0 and readiness.get("scroll_y") == 0:
                        tile, left, top = initial, 0, 0
                    else:
                        remaining_ms = int((deadline - time.monotonic()) * 1000)
                        if remaining_ms <= 0:
                            reasons.add("scan_budget")
                            break
                        monitor.document_value(f"scrollTo({{left:{x}, top:{y}, behavior:'instant'}}); true",
                                               timeout_ms=min(500, remaining_ms))
                        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
                        state = self.wait_for_render(page, 0, timeout_ms=min(FULL_PAGE_TILE_TIMEOUT_MS, remaining_ms),
                                                     allow_empty_tile=True)
                        reasons.update(state["reasons"])
                        for field in ("pending_images", "failed_images"):
                            summary["max_" + field] = max(summary["max_" + field], state.get(field, 0))
                        if (monitor.frame_scope(page.main_frame).get("document_id") != self.baseline_doc
                                or state.get("browser_error_document")):
                            reasons.add("navigation_changed")
                            break
                        # Match each slice to actual scroll coordinates, including bottom clamping.
                        position = monitor.document_value("[scrollX, scrollY]")
                        tile = monitor.viewport_capture()
                        if monitor.frame_scope(page.main_frame).get("document_id") != self.baseline_doc:
                            reasons.add("navigation_changed")
                            break
                        if (position != monitor.document_value("[scrollX, scrollY]") or
                                position != [state.get("scroll_x"), state.get("scroll_y")]):
                            reasons.add("scroll_unstable")
                            break
                        left, top = (round(n) for n in position)
                        summary["visited_viewports"] += 1
                    width, height = document_size()
                    right = min(stitched_width, width, left + tile.width)
                    bottom = min(top + tile.height, height, height_limit)
                    if left > covered_width or top > covered_height or right <= covered_width or bottom <= covered_height:
                        reasons.add("scroll_unreachable")
                        break
                    row_height = min(row_height, bottom - covered_height)
                    if row is None:
                        row = Image.new("RGB", (stitched_width, row_height))
                    source = (covered_width - left, covered_height - top, right - left, covered_height - top + row_height)
                    row.paste(tile.crop(source), (covered_width, 0))
                    covered_width = right
                if covered_width != stitched_width:
                    break
                rows.append(row.crop((0, 0, stitched_width, row_height)))
                covered_height += row_height
                complete = covered_height >= min(height, height_limit)
        except Error:
            reasons.add("inspection_unavailable")

        encoded = self.screenshots["viewport"]
        capture_width, capture_height = initial.size
        if rows:
            image = Image.new("RGB", (stitched_width, covered_height))
            offset = 0
            for strip in rows:
                image.paste(strip, (0, offset))
                offset += strip.height
            rows.clear()
            capture_width, capture_height = image.size
            # A high-entropy raster can exceed the PNG budget even after palette reduction.
            while True:
                try:
                    encoded = as_png(image, 800_000)
                    break
                except ValueError:
                    reasons.add("artifact_budget")
                    capture_height = max(1, capture_height // 2)
                    image = image.crop((0, 0, capture_width, capture_height))
            summary["method"] = "stitched_viewports"
        elif not complete and not readiness.get("browser_error_document"):
            reasons.add("viewport_fallback")
        if capture_width < width or capture_height < height:
            reasons.add("capture_clipped")
        blocked = monitor.blocked_resources + Counter({kind: n for kind, n in monitor.scroll_blocked_requests.items()
                                                       if kind in RENDER_RESOURCES})
        if blocked:
            reasons.add("blocked_resources")
        if monitor.scroll_blocked_navigations:
            reasons.add("scroll_navigation_blocked")
        self.screenshots["full_page"] = encoded
        return {**summary, "status": "partial" if reasons else "ready", "reasons": sorted(reasons),
                "document_width": width if extent_known else None, "document_height": height if extent_known else None,
                "capture_width": capture_width,
                "capture_height": capture_height, "blocked_resources": dict(blocked),
                "scroll_blocked_requests": dict(monitor.scroll_blocked_requests),
                "scroll_blocked_navigations": monitor.scroll_blocked_navigations,
                "waited_ms": round((time.monotonic() - started) * 1000)}

    def select(self, regions: list[dict]) -> list[dict]:
        def priority(row: dict) -> int:
            return (10 * bool(row["intercepts"]) + 8 * bool(row["hidden"]) +
                    4 * bool(row["credential"]) + 3 * bool(row["handlers"]) +
                    2 * (row["tag"] in {"button", "a"}))

        candidates = sorted(regions, key=priority, reverse=True)
        selected = []
        seen_points: set[tuple] = set()
        for row in candidates:
            # Child frames are inspected passively. Parent-frame occlusion and
            # transformed iframe geometry make active child-coordinate probes ambiguous.
            if row["frame"] or row.get("passive_only") or row.get("shadow_path") or row["disabled"] or row["offscreen"] or row["accessibility"]:
                continue
            if not (row["interactive"] or row["intercepts"]) or row["tag"] in {"form", "label", "iframe", "textarea", "select"}:
                continue
            if row["tag"] == "input" and row["input_type"] not in {"button", "submit", "image"}:
                continue
            if self.dangerous.search(row["text"] + " " + row["destination"] + " " + row["selector"]):
                continue
            point = row.get("interception_point") or next((p for p in row["points"] if p["receives"]), None)
            if not point:
                continue
            xy = (point["x"], point["y"])
            if xy in seen_points:
                continue
            seen_points.add(xy)
            selected.append({"row": row, "x": xy[0], "y": xy[1], "hit": point["hit"]})
            if len(selected) == MAX_ACTIONS:
                break
        return selected

    def run_probe(self, sequence: int, target: dict, regions: list[dict]) -> dict:
        row, x, y = target["row"], target["x"], target["y"]
        action = {"id": f"action-{sequence}", "element_id": row["id"], "selector": row["selector"],
                  "expected_receiver": target["hit"], "receiver_verified": False,
                  "baseline_document_id": row["document_id"],
                  "x": x, "y": y, "status": "skipped", "synthetic_fields": 0}
        self.monitor.replay = True
        self.monitor.session = action["id"]
        needs_early = row.get("probe_verification") == "early-replay-required"
        action["early_replay_required"] = needs_early
        context, page = self.open_replay(min(250, self.early_ms / 2) if needs_early else 350)
        try:
            self.monitor.drain(page)
            target_doc = self.monitor.frame_scope(page.main_frame)
            action.update(target_doc)
            if (row["document_id"] != self.baseline_doc or page.main_frame.url != self.baseline_url
                    or target_doc.get("document_id","").partition(":")[2] != row["document_id"].partition(":")[2]):
                action["reason"] = "Baseline and replay document identity differ."
                return action
            self.monitor.action_id, self.monitor.element_id = action["id"], row["id"]
            self.monitor.phase = "precheck"
            self.monitor.request_marks.clear()
            self.monitor.unmatched_routes.clear()
            self.monitor.marker = "PhishGuardTest" + secrets.token_hex(14)
            self.monitor.offline_action = True
            # Resolve target again just before acting. A changed receiver skips the probe.
            verify = "([sel,x,y,hitSel]) => {" + SELECTORS + """
                const el=document.querySelector(sel), hit=hitStack(x,y).hit;
                return !!el && !!hit && (el===hit || el.contains(hit)) && document.querySelector(hitSel)===hit;
            }"""
            args = [row["selector"], x, y, target["hit"]]
            check_hit = "(" + verify + ")(" + json.dumps(args) + ")"
            if not self.monitor.document_value(check_hit):
                action["reason"] = "Receiver changed during baseline replay."
                return action
            if needs_early:
                sampled = round((time.monotonic() - self.loaded_at) * 1000)
                action["early_replay_ms"] = sampled
                if sampled > self.early_ms:
                    action["reason"] = "Early replay verification deadline elapsed."
                    return action
            before = viewport_image(page)
            action["before"] = action["id"] + "-before"
            self.screenshots[action["before"]] = as_png(before, 380000)
            form = row["form"]
            if not form:
                form = next((r["form"] for r in regions if not r["frame"] and
                             r["selector"] in row["intercepts"] and r["form"]), "")
            if form and " >>> " not in form and not self.dangerous.search(form):
                self.monitor.phase = "synthetic_input"
                scope = page.locator(form).first
                fields = [('input[type="email"],input[autocomplete="username"],input[name="username"]',
                           "analyst@example.invalid"), ('input[type="password"]', self.monitor.marker)]
                for field, value in fields:
                    locator = scope.locator(field).first
                    if (locator.count() and locator.evaluate("el=>el.getRootNode()===document")
                            and locator.is_visible() and locator.is_editable()):
                        locator.fill(value, timeout=650)
                        action["synthetic_fields"] += 1
                self.monitor.drain(page)
            if self.monitor.frame_scope(page.main_frame) == target_doc and self.monitor.document_value(check_hit):
                self.monitor.arm_click_observer(target_doc)
                if self.monitor.frame_scope(page.main_frame) != target_doc or not self.monitor.document_value(check_hit):
                    action["reason"] = "Receiver changed before pointer observation."
                    return action
                self.monitor.phase = "click"
                page.mouse.click(x, y)
                action["status"] = "tested"
                page.wait_for_timeout(300)
            else:
                action["reason"] = "Receiver changed after synthetic input."
            self.monitor.drain(page)
            click = self.monitor.native_click
            if click and click.get("document_id") == action["document_id"] and click["action_id"] == action["id"]:
                action["observed_receiver"] = click.get("selector")
                action["receiver_provenance"] = "cdp"
                if action["observed_receiver"] != target["hit"]:
                    action["status"] = "receiver_changed"
                    action["reason"] = "The trusted pointer event named a different receiver."
                else:
                    action["receiver_verified"] = True
            after = viewport_image(page)
            action["after"] = action["id"] + "-after"
            self.screenshots[action["after"]] = as_png(after, 380000)
            action["changed_bbox"] = ImageChops.difference(before, after).getbbox()
            if action["changed_bbox"]:
                self.monitor.record("visual_change", "scanner", {**self.monitor.frame_scope(page.main_frame),
                                    "detail": "Viewport pixels changed after the action."})
            actual = self.monitor.document_value("(() => {" + SELECTORS +
                " return selector(hitStack(" + json.dumps(x) + "," + json.dumps(y) + ").hit);})()")
            action["after_receiver"] = actual
            if not self.monitor.document_value(check_hit):
                self.monitor.record("receiver_change", "scanner", {**self.monitor.frame_scope(page.main_frame), "selector": actual})
        except Error:
            action["reason"] = "Page or target became unavailable during the experiment."
        finally:
            context.close()
            self.monitor.action_id = self.monitor.element_id = None
            self.monitor.phase = "baseline"
            self.monitor.marker = ""
            self.monitor.native_click = None
        return action

    def analyze(self, mode: str) -> dict:
        context, page = self.open_replay()
        try:
            scanner = VisualInteractionScanner(self.monitor)
            early_ms = round((time.monotonic() - self.loaded_at) * 1000)
            self.early_ms = early_ms
            started = time.perf_counter()
            early_image = self.monitor.viewport_capture()
            screenshot_seconds = time.perf_counter() - started
            early_regions = scanner.scan(page, early_image, early=True)
            self.monitor.drain(page)
            earliest = self.loaded_at + (early_ms + PASSIVE_INTERVAL_MS) / 1000
            readiness = self.wait_for_render(page, earliest)
            scanner.coverage["render_readiness"] = readiness
            if readiness["status"] != "ready":
                scanner.coverage["warnings"].append("Viewport capture has rendering limitations (" +
                                                   ", ".join(readiness["reasons"]) + ").")
            late_ms = round((time.monotonic() - self.loaded_at) * 1000)
            started = time.perf_counter()
            initial = self.monitor.viewport_capture()
            self.screenshots["viewport"] = as_png(initial)
            screenshot_seconds += time.perf_counter() - started
            regions = scanner.scan(page, initial)
            changes, limited = compare_checkpoints(early_regions, regions,
                early_complete=scanner.complete_documents["early"], late_complete=scanner.complete_documents["late"])
            if changes:
                started = time.perf_counter()
                self.screenshots["initial"] = as_png(early_image, 380000)
                screenshot_seconds += time.perf_counter() - started
            passive = {"early_ms": early_ms, "late_ms": late_ms, "early_screenshot": "initial" if changes else None,
                       "late_screenshot": "viewport", "changes": changes, "truncated": limited or scanner.coverage["truncated"],
                       "complete_documents": {stage: sorted(ids) for stage, ids in scanner.complete_documents.items()},
                       "probe_exclusions": dict(Counter(r["probe_exclusion"] for r in regions if r["probe_exclusion"])),
                       "uncompared_early_replay_candidates": sum(r.get("probe_verification") == "early-replay-required" for r in regions)}
            self.baseline_url = page.main_frame.url
            self.baseline_doc = self.monitor.frame_scope(page.main_frame).get("document_id")
            started = time.perf_counter()
            annotated = initial.copy()
            draw = ImageDraw.Draw(annotated)
            for row in regions:
                box = row["bbox"]
                if not row["offscreen"] and box["width"] > 0 and box["height"] > 0:
                    draw.rectangle((box["x"], box["y"], box["x"]+box["width"], box["y"]+box["height"]),
                                   outline=PAINT[row["severity"]], width=2)
            self.screenshots["annotated"] = as_png(annotated)
            screenshot_seconds += time.perf_counter() - started
            self.monitor.drain(page)
            final_url = display_url(page.url)
            full_page = self.capture_full_page(page, initial, readiness)
            scanner.coverage.update(full_page_readiness=full_page, full_page_clipped="capture_clipped" in full_page["reasons"],
                                    capture_width=full_page["capture_width"], capture_height=full_page["capture_height"],
                                    viewport_only_hit_testing=True, max_actions=MAX_ACTIONS,
                                    passive_checkpoints=2, active_scope="stable top-level light DOM",
                                    region_visits=scanner.region_visits)
        finally:
            # Closing a context can deliver pending scroll-initiated events.
            # Keep them out of the canonical trace through context disposal.
            context.close()
            self.monitor.phase = "baseline"
        actions = []
        if mode != "javascript-analysis":
            for i, target in enumerate(self.select(regions), start=1):
                actions.append(self.run_probe(i, target, regions))
        scanner.coverage["dropped_events"] = dict(self.monitor.dropped)
        return {"url": display_url(self.url), "final_url": final_url, "viewport": VIEWPORT.copy(),
                "regions": regions, "scripts": self.monitor.scripts, "behavior": self.monitor.behavior,
                "network": self.monitor.network, "interactions": actions, "screenshots": self.screenshots,
                "coverage": scanner.coverage, "passive_changes": passive,
                "_missing_resources": list(self.monitor.missing_resources.values()),
                "performance": {"passive_screenshot_ms": round(screenshot_seconds * 1000, 3)}}
