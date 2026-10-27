"""
SSRF-defended legitimate web endpoint crawler and harvester for PhishGuard AI.
Safely extracts realistic paths and query parameters to debias the training corpus.
"""
import socket
import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin
import urllib.request
from bs4 import BeautifulSoup

from .url_utils import extract_registered_domain, normalize_url

def is_safe_ip(ip_str: str) -> bool:
    """Anti-SSRF defense: Disallow loopback, link-local, multicast, and private RFC1918 IPs."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
        return True
    except ValueError:
        return False

def resolve_and_validate_hostname(hostname: str) -> bool:
    """Ensure host resolves to a public, routable IP address before connecting."""
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if not is_safe_ip(ip_str):
                return False
        return True
    except Exception:
        return False

def crawl_legitimate_domain(
    seed_url: str,
    target_registered_domain: str,
    max_urls: int = 25,
    timeout: int = 5
) -> List[Dict[str, Any]]:
    """
    Crawls a verified legitimate seed domain to discover authentic path and query endpoints.
    SSRF safe: validates IP before opening connection.
    """
    discovered: List[Dict[str, Any]] = []
    visited_urls: Set[str] = set()
    queue = [seed_url]
    
    headers = {
        "User-Agent": "PhishGuard-AI-Security-Research-Crawler/2.0 (+https://github.com/phishguard-ai/research)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9"
    }

    while queue and len(discovered) < max_urls:
        current_url = queue.pop(0)
        norm_current = normalize_url(current_url)
        if norm_current in visited_urls:
            continue
        visited_urls.add(norm_current)

        parsed = urlparse(current_url)
        host = parsed.netloc.split(":")[0]
        if not host or not resolve_and_validate_hostname(host):
            continue

        req = urllib.request.Request(current_url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status_code = response.getcode()
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type.lower():
                    continue
                html_bytes = response.read(250000) # Read up to 250KB max
                html_text = html_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # Record this URL if it has a path or query
        path = parsed.path.strip("/")
        if path or parsed.query:
            discovered.append({
                "url": current_url,
                "norm_url": norm_current,
                "registered_domain": target_registered_domain,
                "parent_url": seed_url,
                "discovery_method": "http_crawl",
                "http_status": status_code,
                "has_path": bool(path),
                "has_query": bool(parsed.query),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        # Parse links
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for tag in soup.find_all(["a", "link", "form"], href=True):
                href = tag.get("href", "").strip()
                if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                    continue
                full_url = urljoin(current_url, href)
                norm_full = normalize_url(full_url)
                cand_domain = extract_registered_domain(full_url)
                
                if cand_domain == target_registered_domain and norm_full not in visited_urls:
                    p = urlparse(full_url)
                    if p.path.strip("/") or p.query:
                        queue.append(full_url)
                        discovered.append({
                            "url": full_url,
                            "norm_url": norm_full,
                            "registered_domain": target_registered_domain,
                            "parent_url": current_url,
                            "discovery_method": "html_link_extraction",
                            "http_status": 200,
                            "has_path": bool(p.path.strip("/")),
                            "has_query": bool(p.query),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                        if len(discovered) >= max_urls:
                            break
        except Exception:
            pass

    return discovered
