from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

try:
    import tldextract  # type: ignore
except Exception:  # pragma: no cover
    tldextract = None

from sklearn.model_selection import StratifiedGroupKFold


REPO_ROOT = Path(__file__).resolve().parents[3]
CLEANED_PATH = REPO_ROOT / "data" / "processed" / "cleaned_dataset.csv"
OUTPUT_DIR = REPO_ROOT / "experiments" / "phase2_validation" / "outputs" / "diagnostics"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def safe_url(raw: object) -> str:
    text = str(raw).strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    return text


def get_host(raw_url: object) -> str:
    url = safe_url(raw_url)
    if not url:
        return ""
    host = urlsplit(url).netloc.lower().split(":", 1)[0]
    return host or ""


def normalize_url(raw_url: object) -> str:
    text = str(raw_url).strip().lower()
    text = re.sub(r"^https?://", "", text)
    text = text.rstrip("/")
    return text


def registrable_domain(raw_url: object) -> str:
    if not raw_url:
        return ""
    url = safe_url(raw_url)
    if tldextract is not None:
        ext = tldextract.extract(url)
        domain = ext.registered_domain or ext.domain
        if domain:
            return domain.lower()
    host = get_host(url)
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:]).lower()
    return host.lower()


def build_split_report(df: pd.DataFrame) -> dict:
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Expected 'url' and 'label' columns in the dataset.")

    y = df["label"].map({"legitimate": 0, "phishing": 1}).rename("target")
    groups = df["url"].map(get_host).rename("host")
    X = df.drop(columns=["url", "label"])

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups))

    X_train = X.iloc[train_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    y_train = y.iloc[train_idx].reset_index(drop=True)
    y_test = y.iloc[test_idx].reset_index(drop=True)
    g_train = groups.iloc[train_idx]
    g_test = groups.iloc[test_idx]

    shared_hosts = set(g_train) & set(g_test)
    feature_cols = [c for c in X.columns if c != "target"]
    train_feature_vectors = X_train.copy()
    test_feature_vectors = X_test.copy()

    train_exact = train_feature_vectors.drop_duplicates().copy()
    test_exact = test_feature_vectors.drop_duplicates().copy()
    test_overlap_rows = test_feature_vectors.merge(
        train_exact,
        how="left",
        on=list(test_feature_vectors.columns),
        indicator=True,
    )
    overlap_count = int((test_overlap_rows["_merge"] == "both").sum())

    report = {
        "rows": int(len(df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "phishing_share_overall": float(y.mean()),
        "phishing_share_train": float(y_train.mean()),
        "phishing_share_test": float(y_test.mean()),
        "hosts_shared_between_train_and_test": int(len(shared_hosts)),
        "exact_feature_vector_overlap_test_in_train": overlap_count,
        "exact_feature_vector_overlap_ratio_test": float(overlap_count / len(X_test)) if len(X_test) else 0.0,
        "feature_columns_count": int(len(feature_cols)),
    }
    return report


def main() -> None:
    if not CLEANED_PATH.exists():
        raise FileNotFoundError(f"Cleaned dataset not found at {CLEANED_PATH}")

    df = pd.read_csv(CLEANED_PATH)

    exact_dups = int(df.duplicated().sum())
    url_dups = int(df["url"].duplicated().sum())
    normalized_dups = int(df["url"].map(normalize_url).duplicated().sum())
    conflicting_urls = df.groupby(df["url"].map(normalize_url))["label"].nunique()
    conflict_url_count = int((conflicting_urls > 1).sum())

    domain_series = df["url"].map(registrable_domain)
    domain_label_counts = (
        df.assign(registrable_domain=domain_series)
        .groupby("registrable_domain")["label"]
        .nunique()
    )
    mixed_domain_count = int((domain_label_counts > 1).sum())

    normalized_url_value_counts = (
        df["url"].map(normalize_url).value_counts().rename_axis("normalized_url").reset_index(name="count")
    )
    repeated_named = normalized_url_value_counts[normalized_url_value_counts["count"] > 1]

    report = {
        "dataset_path": str(CLEANED_PATH),
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "exact_duplicate_rows": exact_dups,
        "duplicate_url_strings": url_dups,
        "duplicate_normalized_urls": normalized_dups,
        "duplicate_urls_with_conflicting_labels": conflict_url_count,
        "unique_registrable_domains": int(domain_series.nunique(dropna=True)),
        "domains_with_mixed_labels": mixed_domain_count,
        "label_distribution": {str(k): int(v) for k, v in df["label"].value_counts().to_dict().items()},
        "missing_value_summary": {str(k): int(v) for k, v in df.isna().sum().to_dict().items() if v > 0},
        "normalized_url_duplicates_preview": repeated_named.head(10).to_dict(orient="records"),
        "split_audit": build_split_report(df),
    }

    manifest_path = OUTPUT_DIR / "duplicate_domain_audit.json"
    manifest_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({
        "rows": int(len(df)),
        "exact_duplicate_rows": exact_dups,
        "duplicate_url_strings": url_dups,
        "duplicate_normalized_urls": normalized_dups,
        "duplicate_urls_with_conflicting_labels": conflict_url_count,
        "unique_registrable_domains": int(domain_series.nunique(dropna=True)),
        "domains_with_mixed_labels": mixed_domain_count,
        "hosts_shared_between_train_and_test": report["split_audit"]["hosts_shared_between_train_and_test"],
        "exact_feature_vector_overlap_test_in_train": report["split_audit"]["exact_feature_vector_overlap_test_in_train"],
        "output": str(manifest_path),
    }, indent=2))


if __name__ == "__main__":
    main()
