"""
URL Normalization and Parsing Utilities for PhishGuard AI.
Public-suffix aware, zero-warning domain extraction and canonicalization.
"""
import re
import ipaddress
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import math
from collections import Counter

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    if not host:
        return False
    # IPv4 check
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Bracketed IPv6 check
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False

def extract_registered_domain(url: str) -> str:
    """Extract public-suffix-aware registered domain (e.g. paypal.com, bbc.co.uk) without deprecation warnings."""
    if not isinstance(url, str) or not url.strip():
        return "unknown_domain"

    if HAS_TLDEXTRACT:
        try:
            ext = tldextract.extract(url)
            if hasattr(type(ext), "top_domain_under_public_suffix"):
                reg_dom = ext.top_domain_under_public_suffix
            elif hasattr(ext, "registered_domain"):
                reg_dom = ext.registered_domain
            else:
                reg_dom = None

            if reg_dom:
                return str(reg_dom).lower()
            elif ext.domain:
                return f"{ext.domain}.{ext.suffix}".strip(".").lower()
        except Exception:
            pass

    # Fallback parser
    u = url.strip()
    if not re.match(r"^[a-zA-Z]+://", u):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        host = parsed.netloc.lower().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        if not host:
            return "unknown_domain"
        if is_ip_address(host):
            return host
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown_domain"

def normalize_url(url: str) -> str:
    """
    Standardize URL:
    - Lowercase scheme and netloc
    - Remove trailing slash if path is otherwise empty
    - Strip fragments (#...)
    - Sort query parameters deterministically
    """
    if not isinstance(url, str) or not url.strip():
        return ""
    u = url.strip()
    if not re.match(r"^[a-zA-Z]+://", u):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove standard default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Path normalization
        path = parsed.path
        if not path or path == "/":
            path = "/"
        else:
            path = re.sub(r"/+", "/", path)

        # Deterministic query sorting
        query = ""
        if parsed.query:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            params.sort(key=lambda x: (x[0], x[1]))
            query = urlencode(params)

        normalized = urlunparse((scheme, netloc, path, "", query, ""))
        return normalized
    except Exception:
        return url.strip().lower()

def compute_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
