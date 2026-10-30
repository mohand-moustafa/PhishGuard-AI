"""
Feature extraction engine for PhishGuard AI.
Extracts lexical, structural, entropy, and token features from URLs.
"""
import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, List
import pandas as pd
import numpy as np

try:
    from data_collection.url_utils import extract_registered_domain, is_ip_address, compute_entropy
except ImportError:
    try:
        from ..data_collection.url_utils import extract_registered_domain, is_ip_address, compute_entropy
    except ImportError:
        from src.data_collection.url_utils import extract_registered_domain, is_ip_address, compute_entropy

LOGIN_PATTERNS = re.compile(r"(login|signin|sign-in|log-in|auth|logon)", re.I)
VERIFY_PATTERNS = re.compile(r"(verify|verification|validate|confirm|confirmation)", re.I)
ACCOUNT_PATTERNS = re.compile(r"(account|profile|user|portal|recover|password|credential)", re.I)
SECURITY_PATTERNS = re.compile(r"(security|secure|update|alert|notice|safeguard|protect)", re.I)
BANKING_PATTERNS = re.compile(r"(bank|banking|paypal|chase|wellsfargo|citi|wire|wallet|billing|invoice|payment)", re.I)
REDIRECT_PATTERNS = re.compile(r"(\bredir(ect)?\b|\burl=|\bdest=|\bto=|\blink=|\bgoto=)", re.I)
PERCENT_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
DOUBLE_ENCODE_PATTERN = re.compile(r"%25[0-9a-fA-F]{2}")
ENCODED_DELIMITER_PATTERN = re.compile(r"%(2[fF]|3[aA]|3[fF]|2[368])")

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "club", "online", "site",
    "buzz", "cam", "fit", "rest", "surf", "cf", "gq", "ml", "tk", "ga"
}

def extract_features_from_url(url: str) -> Dict[str, Any]:
    """Extract standard features from a single URL."""
    if not isinstance(url, str) or not url.strip():
        url = "http://empty.invalid/"

    url_str = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url_str):
        u = "http://" + url_str
    else:
        u = url_str

    try:
        parsed = urlparse(u)
    except Exception:
        parsed = urlparse("http://malformed.invalid/")

    netloc = parsed.netloc.lower()
    host = netloc.split(":")[0]
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    reg_domain = extract_registered_domain(u)

    url_len = len(url_str)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    dots = url_str.count(".")
    hyphens = url_str.count("-")
    underscores = url_str.count("_")
    slashes = url_str.count("/")
    question = url_str.count("?")
    equal = url_str.count("=")
    ampersand = url_str.count("&")
    at = url_str.count("@")

    digits = sum(c.isdigit() for c in url_str)
    letters = sum(c.isalpha() for c in url_str)
    special = url_len - (digits + letters)

    is_https = 1 if parsed.scheme.lower() == "https" else 0
    is_ip = 1 if is_ip_address(host) else 0

    # Token triggers
    has_login = 1 if LOGIN_PATTERNS.search(url_str) else 0
    has_verify = 1 if VERIFY_PATTERNS.search(url_str) else 0
    has_account = 1 if ACCOUNT_PATTERNS.search(url_str) else 0
    has_security = 1 if SECURITY_PATTERNS.search(url_str) else 0
    has_banking = 1 if BANKING_PATTERNS.search(url_str) else 0
    has_redirect = 1 if REDIRECT_PATTERNS.search(url_str) else 0

    tld = reg_domain.split(".")[-1] if "." in reg_domain else ""
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    return {
        "url_length": url_len,
        "host_length": host_len,
        "domain_length": len(reg_domain),
        "path_length": path_len,
        "query_length": query_len,
        "fragment_length": len(fragment),
        "count_dots": dots,
        "count_hyphens": hyphens,
        "count_underscores": underscores,
        "count_slashes": slashes,
        "count_question": question,
        "count_equal": equal,
        "count_ampersand": ampersand,
        "count_at": at,
        "count_digits": digits,
        "count_letters": letters,
        "count_special": special,
        "digit_ratio": digits / url_len if url_len > 0 else 0.0,
        "letter_ratio": letters / url_len if url_len > 0 else 0.0,
        "special_char_ratio": special / url_len if url_len > 0 else 0.0,
        "path_to_url_ratio": path_len / url_len if url_len > 0 else 0.0,
        "query_to_url_ratio": query_len / url_len if url_len > 0 else 0.0,
        "count_subdomains": max(0, len(host.split(".")) - 2) if not is_ip else 0,
        "count_path_segments": len([s for s in path.split("/") if s]),
        "count_percent_encoded": len(PERCENT_PATTERN.findall(url_str)),
        "percent_encoded_ratio": len(PERCENT_PATTERN.findall(url_str)) / url_len if url_len > 0 else 0.0,
        "has_double_encoding": 1 if DOUBLE_ENCODE_PATTERN.search(url_str) else 0,
        "has_punycode": 1 if "xn--" in host else 0,
        "has_unicode": 1 if any(ord(c) > 127 for c in url_str) else 0,
        "count_encoded_delimiters": len(ENCODED_DELIMITER_PATTERN.findall(url_str)),
        "is_ip_host": is_ip,
        "is_https": is_https,
        "host_entropy": compute_entropy(host),
        "domain_entropy": compute_entropy(reg_domain),
        "host_digit_ratio": sum(c.isdigit() for c in host) / host_len if host_len > 0 else 0.0,
        "has_suspicious_tld": has_suspicious_tld,
        "count_query_params": len(parse_qs(query, keep_blank_values=True)),
        "has_redirect_token": has_redirect,
        "has_login_token": has_login,
        "has_verify_token": has_verify,
        "has_account_token": has_account,
        "has_security_token": has_security,
        "has_banking_token": has_banking,
        "path_entropy": compute_entropy(path),
        "query_entropy": compute_entropy(query),
        "url_entropy": compute_entropy(url_str)
    }

def extract_features_df(df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
    """Extract features across a pandas DataFrame."""
    records = []
    for u in df[url_col]:
        records.append(extract_features_from_url(u))
    return pd.DataFrame(records)
