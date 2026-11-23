"""Bounded syntax-tree inspection. Page-supplied JavaScript is parsed as UTF-8 data."""
from __future__ import annotations

from typing import Any

# A rule's confidence describes the observed operation. Runtime evidence is needed
# to infer intent. Standard platform features receive informational severity.
RULES = {
    "dynamic-code": ("low", "Constructs or evaluates JavaScript at runtime."),
    "decoded-execution": ("medium", "Passes the result of a decoding call directly into a dynamic code evaluator."),
    "decode": ("informational", "Decodes a string or byte sequence."),
    "repeated-decoding": ("low", "Multiple decoding calls occur within one script."),
    "encoded-literal": ("low", "A string contains many hexadecimal or Unicode escape sequences."),
    "inject-script": ("low", "Creates a script element dynamically."),
    "inject-frame": ("low", "Creates an iframe dynamically."),
    "create-form": ("informational", "Constructs a form in script."),
    "hidden-control": ("low", "Sets a form control or DOM element to a hidden state."),
    "inject-markup": ("informational", "Writes HTML markup into the document."),
    "listener": ("informational", "Registers an event listener or assigns an event handler."),
    "credential-read": ("low", "Reads the value of a credential-related control."),
    "form-submit": ("low", "Requests form submission from script."),
    "form-destination": ("low", "Assigns a form submission destination."),
    "navigate": ("low", "Changes the page's navigation destination."),
    "popup": ("low", "Requests a new browsing context."),
    "clipboard": ("low", "Accesses the clipboard interface."),
    "message-wildcard": ("low", "Sends a cross-window message with an unrestricted target origin."),
    "fingerprint": ("informational", "Reads a browser fingerprinting surface."),
    "debug-detection": ("informational", "Contains debugger or automation-detection logic."),
    "form-data": ("informational", "Builds form data from an element for possible serialization."),
}

EQUIVALENT_EVENTS = {
    "dynamic-code": {"script_parsed"}, "inject-script": {"script_inserted"},
    "inject-frame": {"iframe_inserted"}, "form-submit": {"form_submission"},
    "credential-read": {"credential_access"}, "navigate": {"redirect"},
    "popup": {"popup", "popup_attempt"}, "clipboard": {"clipboard_read", "clipboard_write"},
    "listener": {"listener_registration"},
}

def same_document(first: dict, second: dict) -> bool:
    """Require worker-owned document identity. A document URL can name multiple frames."""
    return bool(first.get("document_id") and first.get("frame_key")
                and first["document_id"] == second.get("document_id")
                and first["frame_key"] == second.get("frame_key"))


class JavaScriptStaticAnalyzer:
    """Parse inline, handler, external and dynamically observed sources with byte/AST budgets."""
    max_scripts = 40
    max_bytes = 384_000
    per_script = 48_000
    node_budget = 70_000
    finding_limit = 256

    def analyze(self, scripts: list[dict], events: list[dict]) -> tuple[list[dict], dict]:
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript
        except ImportError:
            return [], {"status": "unavailable", "reason": "tree-sitter JavaScript grammar missing"}

        parser = Parser(Language(tree_sitter_javascript.language()))
        findings: list[dict] = []
        visited = consumed = parsed = syntax_errors = 0
        partial = len(scripts) > self.max_scripts
        for script in scripts[:self.max_scripts]:
            available = min(self.per_script, self.max_bytes - consumed)
            if available <= 0 or len(findings) >= self.finding_limit or visited >= self.node_budget:
                partial = True
                break
            text = script.get("code") or ""
            if not isinstance(text, str):
                continue
            data = text[:available].encode("utf-8", errors="replace")[:available]
            partial |= len(text) > available or len(data) == available
            if not data.strip():
                continue
            consumed += len(data)
            tree = parser.parse(data)
            parsed += 1
            syntax_errors += int(tree.root_node.has_error)
            seen_rules: set[tuple] = set()
            decode_count = 0
            stack = [tree.root_node]
            while stack:
                if visited >= self.node_budget or len(findings) >= self.finding_limit:
                    partial = True
                    break
                node = stack.pop()
                visited += 1
                rule = self._rule(node, data)
                if rule == "decode":
                    decode_count += 1
                    if decode_count >= 3:
                        rule = "repeated-decoding"
                if rule:
                    selector = (script.get("selector") if script.get("kind") == "handler" else None)
                    selector = selector or self._listener_selector(node, data) or script.get("selector")
                    # Two external callbacks can use the same API on different controls.
                    key = (rule, selector, node.start_byte if not selector and script.get("kind") == "external" else None)
                    if key not in seen_rules:
                        seen_rules.add(key)
                        findings.append(self._finding(rule, node, data, {**script, "selector": selector},
                                                      events, len(findings)))
                # A large array of tiny nodes is bounded by the per-script byte limit.
                stack.extend(reversed(node.named_children))
        return findings, {"status": "partial" if partial or syntax_errors else "complete",
                          "parser": "tree-sitter-javascript", "scripts_parsed": parsed,
                          "bytes_parsed": consumed, "nodes_examined": visited,
                          "scripts_with_syntax_errors": syntax_errors, "limited": partial}

    @staticmethod
    def _rule(node: Any, data: bytes) -> str | None:
        def source(part: Any, limit: int = 240) -> str:
            if part is None:
                return ""
            return data[part.start_byte:min(part.end_byte, part.start_byte + limit)].decode("utf-8", "replace")

        kind = node.type
        if kind == "debugger_statement":
            return "debug-detection"
        if kind == "string":
            literal = source(node, 640)
            if literal.count("\\x") + literal.count("\\u") >= 8:
                return "encoded-literal"
        if kind == "member_expression":
            prop = source(node.child_by_field_name("property"))
            obj = source(node.child_by_field_name("object"))
            if prop == "webdriver":
                return "debug-detection"
            if prop in {"deviceMemory", "hardwareConcurrency"}:
                return "fingerprint"
            if prop == "clipboard" and "navigator" in obj:
                return "clipboard"
            if prop == "value" and any(word in obj.lower() for word in ("password", "passwd", "credential")):
                return "credential-read"
        if kind == "assignment_expression":
            left = source(node.child_by_field_name("left")).replace(" ", "")
            rhs = source(node.child_by_field_name("right"))
            if left in {"location", "location.href", "window.location", "window.location.href",
                        "document.location", "document.location.href", "top.location", "self.location"}:
                return "navigate"
            prop = left.rsplit(".", 1)[-1]
            if prop == "action" or prop == "formAction":
                return "form-destination"
            if prop in {"innerHTML", "outerHTML"}:
                return "inject-markup"
            if prop.startswith("on") and prop[2:] in {"click", "submit", "input", "pointerdown", "keydown"}:
                return "listener"
            if (prop == "type" and rhs.strip("'\u0022") == "hidden") or (prop == "hidden" and rhs == "true"):
                return "hidden-control"
        if kind not in {"call_expression", "new_expression"}:
            return None
        callee = source(node.child_by_field_name("function") or node.child_by_field_name("constructor"))
        name = callee.rsplit(".", 1)[-1]
        args = node.child_by_field_name("arguments")
        if kind == "new_expression" and callee in {"FormData", "window.FormData", "globalThis.FormData"}:
            if args is not None and args.named_child_count:
                return "form-data"
        literals = [source(child).strip("'\u0022") if child.type == "string" else None
                    for child in (args.named_children[:3] if args is not None else [])]
        if callee in {"eval", "window.eval", "globalThis.eval", "Function", "window.Function", "globalThis.Function"}:
            if args is not None:
                for child in args.named_children[:3]:
                    if child.type == "call_expression":
                        qualified = source(child.child_by_field_name("function"))
                        if qualified in {"atob", "window.atob", "globalThis.atob", "String.fromCharCode",
                                         "decodeURIComponent", "unescape"}:
                            return "decoded-execution"
            return "dynamic-code"
        if name in {"atob", "fromCharCode", "decodeURIComponent", "unescape"}:
            return "decode"
        if name == "createElement" and literals:
            return {"script": "inject-script", "iframe": "inject-frame", "form": "create-form"}.get(literals[0])
        if name in {"requestSubmit", "submit"}:
            return "form-submit"
        if name == "setAttribute" and literals and literals[0] in {"action", "formaction"}:
            return "form-destination"
        if name == "setAttribute" and literals[:2] == ["type", "hidden"]:
            return "hidden-control"
        if name == "postMessage" and len(literals) > 1 and literals[1] == "*":
            return "message-wildcard"
        if name == "addEventListener":
            return "listener"
        if callee.endswith(("location.assign", "location.replace")):
            return "navigate"
        if callee in {"open", "window.open", "globalThis.open"}:
            return "popup"
        if callee.endswith(("document.write", "document.writeln", "insertAdjacentHTML")):
            return "inject-markup"
        if name in {"toDataURL", "getImageData", "getSupportedExtensions"}:
            return "fingerprint"
        return None

    @staticmethod
    def _listener_selector(node: Any, data: bytes) -> str | None:
        """Resolve only literal document.querySelector/getElementById listener registrations."""
        def text(n):
            return data[n.start_byte:n.end_byte] if n is not None and n.end_byte - n.start_byte <= 200 else b""

        for _ in range(24):
            if node is None:
                break
            if node.type == "call_expression":
                call = node.child_by_field_name("function")
                if call and text(call.child_by_field_name("property")) == b"addEventListener":
                    owner = call.child_by_field_name("object")
                    if owner and owner.type == "call_expression":
                        lookup = text(owner.child_by_field_name("function"))
                        args = owner.child_by_field_name("arguments")
                        literal = args.named_child(0) if args and args.named_child_count == 1 else None
                        if literal and literal.type == "string":
                            value = text(literal)[1:-1].decode("utf-8", "replace")
                            if value and "\\" not in value:
                                if lookup == b"document.querySelector":
                                    return value
                                if lookup == b"document.getElementById" and value.isidentifier():
                                    return "#" + value
            node = node.parent
        return None

    @staticmethod
    def _finding(rule: str, node: Any, data: bytes, script: dict, events: list[dict], index: int) -> dict:
        selector, source = script.get("selector"), script.get("source")
        related = []
        for event in events[:1000]:
            if event.get("type") not in EQUIVALENT_EVENTS.get(rule, set()):
                continue
            if not same_document(script, event):
                continue
            same_element = selector and selector == event.get("selector")
            if same_element or (source and source == event.get("initiator")):
                related.append(event.get("id"))
        severity, explanation = RULES[rule]
        header = None
        if script.get("kind") == "external":
            parent = node
            for _ in range(24):
                if parent is None:
                    break
                if parent.type in {"arrow_function", "function_expression", "function_declaration"}:
                    body = parent.child_by_field_name("body")
                    if body is not None:
                        def position(n):
                            # CDP uses UTF-16 column offsets, tree-sitter uses UTF-8 byte offsets.
                            start = n.start_byte - n.start_point.column
                            prefix = data[start:n.start_byte].decode("utf-8", "replace")
                            return [n.start_point.row + 1, len(prefix.encode("utf-16-le")) // 2 + 1]
                        header = [position(parent), position(body)]
                    break
                parent = parent.parent
        return {"id": f"js-{index+1}", "rule_id": f"js.{rule}", "severity": severity,
                "confidence": 0.85, "source": source, "kind": script.get("kind"),
                "line": node.start_point.row + 1, "column": node.start_point.column + 1,
                "snippet": data[node.start_byte:min(node.end_byte, node.start_byte + 160)].decode("utf-8", "replace"),
                "selector": selector, "element_id": None, "frame_key": script.get("frame_key"),
                "document_id": script.get("document_id"), "action_id": script.get("action_id"),
                "association": "unresolved", "function_header": header, "evidence_status": "static_observation",
                "confidence_scope": "syntax", "malicious_intent": "undetermined",
                "explanation": explanation, "related_events": [event_id for event_id in related if event_id][:20]}
