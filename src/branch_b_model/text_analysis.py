"""Unicode-preserving text cleanup and configurable keyword features."""
import re
from collections import Counter

def clean_text(text):
    """Normalize whitespace/newlines while preserving punctuation and Unicode."""
    text = "" if text is None else str(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[\t\f\v ]+", " ", line).strip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line)

def find_keywords(text, keywords):
    """Find case-insensitive whole-phrase matches, preserving recognized spelling."""
    found = []
    source = text or ""
    for keyword in keywords:
        escaped = re.escape(keyword.strip())
        pattern = re.compile(r"(?<![\w])" + escaped + r"(?![\w])", re.IGNORECASE | re.UNICODE)
        for match in pattern.finditer(source):
            found.append({"keyword": keyword, "matched_text": match.group(0),
                          "start": match.start(), "end": match.end()})
    return sorted(found, key=lambda item: item["start"])

def keyword_counts(keyword_matches):
    """Count configured keyword occurrences."""
    return dict(Counter(item["keyword"] for item in keyword_matches))
