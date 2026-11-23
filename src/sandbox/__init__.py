"""Isolated interactive evidence collection and phishing analysis."""

# Shared by the capture broker, archive verifier and disconnected renderer.
REPLAY_HEADERS = frozenset({"content-type", "content-security-policy", "x-frame-options",
                            "x-content-type-options", "permissions-policy", "referrer-policy"})
