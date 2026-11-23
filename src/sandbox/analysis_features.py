"""Single-row inference features, ported from Advanced_Feature_Engineering_PCA_Analysis.

The training notebook rounds entropy and uses its own compound-suffix list. Keep
these definitions aligned with the fitted scaler and PCA stored in models/.
"""


import math
import re
import string
from urllib.parse import urlsplit

from src.data_collection.url_utils import compute_entropy


BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram', 'netflix', 'whatsapp',
    'linkedin', 'dropbox', 'adobe', 'docusign', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    'dhl', 'fedex', 'usps', 'outlook', 'office365', 'onedrive', 'binance', 'coinbase', 'metamask', 'steam',
    'ebay', 'yahoo'
]


SHORTENERS = {
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'qrco.de', 'q-r.to', 'l.ead.me', 't.ly', 'rb.gy', 'tiny.cc', 'bl.ink', 'v.gd',
    'lnkd.in', 's.id', 'qr.codes', 'forms.gle'
}


FREE_HOSTING = {
    'docs.google.com', 'sites.google.com', 'drive.google.com', 'wixsite.com', 'weebly.com',
    'blogspot.com', 'github.io', 'gitlab.io', 'firebaseapp.com', 'web.app', 'netlify.app', 'pages.dev',
    'vercel.app', 'herokuapp.com', '000webhostapp.com', 'notion.site', 'express.adobe.com',
    'dropbox.com', 'canva.com', 'sharepoint.com', 'typeform.com', 'webflow.io', 'glitch.me',
    'repl.co', 'wordpress.com', 'myshopify.com', 'azurewebsites.net', 'cloudfront.net',
    's3.amazonaws.com', 'storage.googleapis.com', 'linktr.ee', 'carrd.co', 'godaddysites.com',
    'square.site', 'jimdofree.com', 'mystrikingly.com', 'yolasite.com'
}


RISKY_TLDS = {
    'xyz', 'top', 'shop', 'cyou', 'icu', 'buzz', 'click', 'link', 'live', 'online', 'site', 'store',
    'tk', 'ml', 'ga', 'cf', 'gq', 'cfd', 'sbs', 'rest', 'monster', 'bond', 'lol', 'vip', 'work',
    'support', 'win', 'loan', 'men', 'date', 'racing', 'review', 'stream', 'download', 'zip', 'mov'
}


RISKY_EXT = {'php', 'asp', 'aspx', 'jsp', 'exe', 'apk', 'zip', 'scr', 'js', 'cgi'}


SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'secure', 'verify', 'account', 'update', 'confirm', 'banking', 'wallet',
    'password', 'support', 'billing', 'unlock', 'suspend', 'alert', 'webmail', 'recovery',
    'authentication', 'payment'
]


REDIRECT_PARAMS = {
    'url', 'redirect', 'redirect_url', 'return', 'return_url',
    'next', 'continue', 'target', 'dest', 'destination'
}


SECOND_LEVEL_LABELS = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'mil', 'gob', 'nom'}


VOWELS = set('aeiou')


IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def safe_parse(url):
    s = str(url).strip()
    if '://' not in s:
        s = 'http://' + s
    return urlsplit(s)


def get_host(url):
    p = safe_parse(url)
    h = p.netloc.lower()
    return h.split(':')[0] if ':' in h else h


def split_host(host):
    labels = host.split('.')
    if len(labels) < 2:
        return '', host, ''
    k = 1
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_LABELS:
        k = 2  # Handle compound ccTLDs (e.g. gov.tr, co.uk)
    suffix = '.'.join(labels[-k:])
    sld = labels[-k - 1]
    sub = '.'.join(labels[:-k - 1])
    return sub, sld, suffix


def shannon(text: str) -> float:
    return round(compute_entropy(text), 4)


def parse_ctx(url):
    u = str(url).strip()
    p = safe_parse(u)
    host = get_host(u)
    is_ip = bool(IP_RE.match(host)) or ':' in host or bool(re.fullmatch(r'0x[0-9a-f]+|\d{8,10}', host))
    if is_ip:
        sub, sld, suffix = '', host, ''
    else:
        sub, sld, suffix = split_host(host)
    return {'url': u, 'p': p, 'host': host, 'sub': sub, 'sld': sld, 'suffix': suffix, 'is_ip': is_ip}


def extract_url_structure(ctx):
    u, p, host = ctx['url'], ctx['p'], ctx['host']
    path = p.path or ''
    query = p.query or ''
    fragment = p.fragment or ''

    u_len = len(u)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)
    frag_len = len(fragment)

    segs = [s for s in path.split('/') if s]
    q_params = [q for q in query.split('&') if q]

    return {
        'path_length': path_len,
        'query_length': query_len,
        'fragment_length': frag_len,
        'path_depth': len(segs),
        'num_path_segments': len(segs),
        'num_query_params': len(q_params),
        'path_url_ratio': round(path_len / max(u_len, 1), 6),
        'query_url_ratio': round(query_len / max(u_len, 1), 6),
        'hostname_url_ratio': round(host_len / max(u_len, 1), 6),
        'ends_with_slash': int(u.endswith('/')),
        'is_http': int(u.lower().startswith('http://'))
    }


def extract_hostname_subdomain(ctx):
    p, host, sub, sld, suffix, is_ip = ctx['p'], ctx['host'], ctx['sub'], ctx['sld'], ctx['suffix'], ctx['is_ip']
    host_len = len(host)

    h_tokens = [t for t in re.split(r'[.\-]', host) if t]
    sub_labels = [l for l in sub.split('.') if l]
    tld = suffix.split('.')[-1] if suffix else ''

    try:
        port = p.port
    except ValueError:
        port = None

    unique_h = len(set(host))
    consec_repeats = sum(1 for i in range(len(host) - 1) if host[i] == host[i+1])

    return {
        'sld_length': len(sld),
        'tld_length': len(tld),
        'sub_depth': len(sub_labels),
        'host_num_tokens': len(h_tokens),
        'host_longest_token': max((len(t) for t in h_tokens), default=0),
        'sld_has_digit': int(any(ch.isdigit() for ch in sld)),
        'has_ip_host': int(is_ip),
        'has_punycode': int('xn--' in host),
        'has_userinfo': int('@' in p.netloc),
        'has_nonstd_port': int(port is not None and port not in (80, 443)),
        'avg_subdomain_length': round(sum(len(s) for s in sub_labels) / max(len(sub_labels), 1), 4),
        'max_subdomain_length': max((len(s) for s in sub_labels), default=0),
        'subdomain_length_ratio': round(sum(len(s) for s in sub_labels) / max(host_len, 1), 6),
        'hostname_unique_char_ratio': round(unique_h / max(host_len, 1), 6),
        'hostname_alpha_ratio': round(sum(c.isalpha() for c in host) / max(host_len, 1), 6),
        'hostname_special_ratio': round(sum(not c.isalnum() and c not in '.-' for c in host) / max(host_len, 1), 6),
        'consecutive_repeat_count': consec_repeats
    }


def extract_sld_randomness(ctx):
    host, sub, sld = ctx['host'], ctx['sub'], ctx['sld']
    clean_sld = sld.replace('xn--', '')

    sld_letters = [ch for ch in clean_sld if ch.isalpha()]
    sld_runs = re.findall(r'[^aeiou\W\d_]+', clean_sld)
    sld_chars = [ch for ch in clean_sld if ch.isalnum()]
    sld_switches = sum(1 for a, b in zip(sld_chars, sld_chars[1:]) if a.isdigit() != b.isdigit())

    return {
        'sld_entropy': shannon(clean_sld),
        'sld_max_consonant_run': max((len(r) for r in sld_runs), default=0),
        'sld_vowel_ratio': round(sum(ch in VOWELS for ch in sld_letters) / len(sld_letters), 4) if sld_letters else 0.0,
        'sld_digit_letter_switches': sld_switches,
        'domain_entropy': shannon('.'.join(host.split('.')[-2:]) if len(host.split('.')) >= 2 else host),
        'subdomain_entropy': shannon(sub)
    }


def extract_lexical_semantics(ctx):
    u, host = ctx['url'], ctx['host']
    u_lower = u.lower()
    u_len = len(u)

    vowels = sum(c in 'aeiou' for c in u_lower)
    consonants = sum(c in 'bcdfghjklmnpqrstvwxyz' for c in u_lower)
    char_types = sum([
        any(c.islower() for c in u),
        any(c.isupper() for c in u),
        any(c.isdigit() for c in u),
        any(c in string.punctuation for c in u)
    ])
    url_tokens = [t for t in re.split(r'[^a-zA-Z0-9]+', u) if t]
    tok_lens = [len(t) for t in url_tokens] if url_tokens else [0]

    return {
        'vowel_ratio': round(vowels / max(u_len, 1), 6),
        'consonant_ratio': round(consonants / max(u_len, 1), 6),
        'character_diversity': char_types / 4.0,
        'unique_char_ratio': round(len(set(u)) / max(u_len, 1), 6),
        'punctuation_ratio': round(sum(c in string.punctuation for c in u) / max(u_len, 1), 6),
        'token_count': len(url_tokens),
        'avg_token_length': round(sum(tok_lens) / max(len(tok_lens), 1), 4),
        'max_token_length': max(tok_lens),
        'suspicious_token_count': sum(t.lower() in SUSPICIOUS_KEYWORDS for t in url_tokens),
        'host_kw_count': sum(host.count(k) for k in SUSPICIOUS_KEYWORDS)
    }


def extract_path_query(ctx):
    p = ctx['p']
    path = p.path or ''
    query = p.query or ''
    pq = path + ('?' + query if query else '')
    low_pq = pq.lower()

    p_tokens = [t for t in re.split(r'[^a-zA-Z0-9]+', path) if t]
    p_tok_lens = [len(t) for t in p_tokens] if p_tokens else [0]
    ext_match = re.search(r'\.([a-z0-9]{2,5})$', path.lower())
    ext = ext_match.group(1) if ext_match else ''

    q_params = [q for q in query.split('&') if q]
    param_lens = []
    has_redirect = 0
    for qp in q_params:
        if '=' in qp:
            k, v = qp.split('=', 1)
            param_lens.append(len(v))
            if k.lower() in REDIRECT_PARAMS:
                has_redirect = 1
        else:
            param_lens.append(len(qp))
            if qp.lower() in REDIRECT_PARAMS:
                has_redirect = 1

    has_embedded_url = int(bool(re.search(r'https?://|www\.', path + '?' + query, re.IGNORECASE)))

    return {
        'num_path_tokens': len(p_tokens),
        'avg_path_token_length': round(sum(p_tok_lens) / max(len(p_tok_lens), 1), 4),
        'max_path_token_length': max(p_tok_lens),
        'path_digit_ratio': round(sum(ch.isdigit() for ch in path) / len(path), 6) if path else 0.0,
        'path_special_chars': sum(pq.count(ch) for ch in '%@&_~+$!*'),
        'path_kw_count': sum(low_pq.count(k) for k in SUSPICIOUS_KEYWORDS),
        'path_has_risky_ext': int(ext in RISKY_EXT),
        'path_longest_token': max((len(t) for t in re.split(r'[/\-_.=&?]', pq) if t), default=0),
        'avg_query_param_length': round(sum(param_lens) / max(len(param_lens), 1), 4) if param_lens else 0.0,
        'long_query_param_count': sum(l > 25 for l in param_lens),
        'has_embedded_url': has_embedded_url,
        'has_redirect_param': has_redirect
    }


def extract_obfuscation(ctx):
    u = ctx['url']
    u_len = len(u)

    pct_matches = re.findall(r'%[0-9a-fA-F]{2}', u)
    pct_count = len(pct_matches)
    hex_seqs = re.findall(r'0x[0-9a-fA-F]+|[0-9a-fA-F]{8,}', u)
    encoded_delims = re.findall(r'%(?:2f|3f|3d|26|23|20)', u, re.IGNORECASE)
    unusual_cnt = sum((ord(c) > 126 or ord(c) < 32 or c in '<>{}|\\^~[]`') for c in u)
    mixed_encoded = int(pct_count > 0 and any(c in u for c in '?&=#'))
    obf_density = (pct_count * 2.0 + len(encoded_delims) * 3.0 + unusual_cnt * 2.0) / max(u_len, 1)

    return {
        'pct_encoded_count': pct_count,
        'encoded_char_ratio': round((pct_count * 3) / max(u_len, 1), 6),
        'hex_sequence_count': len(hex_seqs),
        'encoded_delimiter_count': len(encoded_delims),
        'unusual_char_count': unusual_cnt,
        'num_non_ascii': sum(ord(ch) > 127 for ch in u),
        'is_mixed_encoded': mixed_encoded,
        'obfuscation_density': round(obf_density, 6)
    }


def extract_entropy_casing(ctx):
    u, host, p = ctx['url'], ctx['host'], ctx['p']
    path = p.path or ''
    query = p.query or ''
    pq = path + ('?' + query if query else '')
    u_len = len(u)

    host_ent = shannon(host)
    path_ent = shannon(pq)
    query_ent = shannon(query)
    unique_h = len(set(host))
    h_norm_ent = host_ent / math.log2(max(unique_h, 2)) if unique_h > 1 else 0.0
    max_comp_ent = max(host_ent, path_ent, query_ent)

    upper_cnt = sum(c.isupper() for c in u)
    lower_cnt = sum(c.islower() for c in u)

    return {
        'host_entropy': host_ent,
        'path_entropy': path_ent,
        'query_entropy': query_ent,
        'hostname_entropy_normalized': round(h_norm_ent, 6),
        'max_component_entropy': max_comp_ent,
        'uppercase_ratio': round(upper_cnt / max(u_len, 1), 6),
        'lowercase_ratio': round(lower_cnt / max(u_len, 1), 6),
        'is_all_lowercase': int(upper_cnt == 0),
        'repeated_char_ratio_url': round(1.0 - (len(set(u)) / max(u_len, 1)), 6)
    }


def extract_platform_brands(ctx):
    host, sub, sld, suffix = ctx['host'], ctx['sub'], ctx['sld'], ctx['suffix']
    tld = suffix.split('.')[-1] if suffix else ''

    in_sub = int(any(b in sub for b in BRANDS))
    in_sld_inexact = int(any((b in sld) and (sld != b) for b in BRANDS))
    brand_impersonation = int(in_sub or in_sld_inexact)

    on_platform = lambda doms: any(host == d or host.endswith('.' + d) for d in doms)
    short = int(on_platform(SHORTENERS))
    free = int(on_platform(FREE_HOSTING))
    shared_platform = int(short or free)

    return {
        'is_shortener': short,
        'is_free_hosting': free,
        'is_shared_platform': shared_platform,
        'tld_risky': int(tld in RISKY_TLDS),
        'tld_is_gov_edu': int(any(l in {'gov', 'edu', 'mil'} for l in suffix.split('.'))),
        'brand_in_subdomain': in_sub,
        'brand_in_sld_inexact': in_sld_inexact,
        'brand_impersonation': brand_impersonation
    }

def model_features(url: str) -> dict[str, float]:
    """Extract the raw columns consumed by the stored 87-feature transformer."""
    ctx = parse_ctx(url)
    host = ctx["host"]
    result = {}
    for extract in (extract_url_structure, extract_hostname_subdomain, extract_sld_randomness,
                    extract_lexical_semantics, extract_path_query, extract_obfuscation,
                    extract_entropy_casing, extract_platform_brands):
        result.update(extract(ctx))

    url_length = max(1, len(url))
    host_length = max(1, len(host))
    entropy = shannon(url)
    dots = url.count(".")
    hyphens = url.count("-")
    subdomains = max(0, host.count(".") - 1)
    question_marks = url.count("?")
    equals = url.count("=")
    result.update(
        url_length=len(url), length_hostname=len(host), num_www=host.count("www."),
        num_subdomains=subdomains, num_dots=dots, num_hyphens=hyphens,
        num_question_mark=question_marks, num_eq=equals, prefix_suffix=int("-" in host),
        ratio_digits_url=round(sum(c.isdigit() for c in url) / url_length, 4),
        ratio_digits_host=round(sum(c.isdigit() for c in host) / host_length, 4),
        entropy=entropy, has_path=int(len(ctx["p"].path) > 1),
        dots_hostname_ratio=round(dots / host_length, 6),
        hyphens_hostname_ratio=round(hyphens / host_length, 6),
        subdomains_hostname_ratio=round(subdomains / host_length, 6),
        special_chars_url_ratio=round((dots + hyphens + question_marks + equals) / url_length, 6),
        entropy_length_ratio=round(entropy / url_length, 6),
        hostname_entropy_length_ratio=round(result["host_entropy"] / host_length, 6),
        path_entropy_ratio=round(result["path_entropy"] / max(entropy, 0.001), 6),
        # In training, (age_clean < 365) is False when the age is missing.
        young_brand_impersonation=0,
    )
    return result
