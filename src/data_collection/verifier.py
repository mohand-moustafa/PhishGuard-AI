"""
Candidate Verification and Quarantine Engine for PhishGuard AI.
Enforces multi-factor verification before any candidate URL is admitted into training data.
"""
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

from .url_utils import extract_registered_domain, normalize_url

class CandidateVerifier:
    def __init__(self, check_live_dns: bool = True):
        self.check_live_dns = check_live_dns
        self._dns_cache: Dict[str, bool] = {}

    def is_domain_resolvable(self, hostname: str) -> bool:
        """Verify whether a hostname currently resolves via DNS."""
        if not hostname:
            return False
        if hostname in self._dns_cache:
            return self._dns_cache[hostname]
        try:
            socket.gethostbyname(hostname)
            self._dns_cache[hostname] = True
            return True
        except (socket.gaierror, socket.herror, Exception):
            self._dns_cache[hostname] = False
            return False

    def verify_candidate(
        self,
        candidate_record: Dict[str, Any],
        expected_class: str = "legitimate"
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify a candidate record.
        Returns:
            (is_verified, status_reason, verification_metadata)
        """
        url = candidate_record.get("url", "")
        if not url or not isinstance(url, str):
            return False, "EMPTY_OR_INVALID_URL", {}

        norm = normalize_url(url)
        parsed = urlparse(norm)
        host = parsed.netloc.split(":")[0]

        if not host:
            return False, "MALFORMED_URL_NO_HOST", {}

        reg_domain = extract_registered_domain(url)
        target_domain = candidate_record.get("registered_domain") or reg_domain

        # 1. Domain consistency
        if reg_domain != target_domain:
            return False, f"DOMAIN_MISMATCH: {reg_domain} != {target_domain}", {}

        # 2. DNS check if enabled
        dns_ok = True
        if self.check_live_dns:
            dns_ok = self.is_domain_resolvable(host)
            if not dns_ok and expected_class == "legitimate":
                return False, f"DNS_RESOLUTION_FAILED for host {host}", {}

        # 3. Structural check
        path = parsed.path.strip("/")
        has_path = bool(path)
        has_query = bool(parsed.query)

        now_ts = datetime.now(timezone.utc).isoformat()
        metadata = {
            "url": url,
            "norm_url": norm,
            "registered_domain": reg_domain,
            "verified_label": expected_class,
            "verification_status": "VERIFIED" if dns_ok else "QUARANTINED",
            "verification_method": "multi_factor_dns_and_domain_consistency",
            "verification_timestamp": now_ts,
            "has_path": has_path,
            "has_query": has_query,
            "dns_resolvable": dns_ok
        }

        return True, "VERIFIED_VALID", metadata
