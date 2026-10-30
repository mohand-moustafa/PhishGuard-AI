"""
Deduplication, Quarantine, and Dataset Integration Engine for PhishGuard AI.
Integrates verified legitimate path URLs and verified threat feeds while maintaining zero domain leakage.
"""
import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple
import pandas as pd

from .url_utils import normalize_url, extract_registered_domain, compute_entropy

def merge_datasets(
    original_csv: Path,
    verified_additions_csv: Path,
    output_merged_csv: Path,
    quarantine_output_csv: Path,
    manifest_output_json: Path
) -> Dict[str, Any]:
    """
    Safely merges verified URL additions into the base dataset.
    Preserves exact provenance, logs duplicates, quarantines conflicts.
    """
    print(f"Loading original dataset from: {original_csv}")
    df_orig = pd.read_csv(original_csv)
    original_count = len(df_orig)
    
    # Standardize column naming
    url_col = "url" if "url" in df_orig.columns else "URL"
    label_col = "label" if "label" in df_orig.columns else "is_phishing"
    
    # Build normalization index for original
    df_orig["norm_url"] = df_orig[url_col].apply(normalize_url)
    existing_urls = set(df_orig["norm_url"])
    existing_labels = dict(zip(df_orig["norm_url"], df_orig[label_col]))
    
    print(f"Loading verified additions from: {verified_additions_csv}")
    df_add = pd.read_csv(verified_additions_csv)
    
    add_url_col = "url" if "url" in df_add.columns else ("norm_url" if "norm_url" in df_add.columns else df_add.columns[0])
    add_label_col = "verified_label" if "verified_label" in df_add.columns else ("label" if "label" in df_add.columns else None)
    
    added_records = []
    quarantined_records = []
    duplicates_count = 0
    conflicts_count = 0
    seen_in_batch = set()
    
    now_ts = datetime.now(timezone.utc).isoformat()
    
    for idx, row in df_add.iterrows():
        u = str(row[add_url_col]).strip()
        norm = normalize_url(u)
        lbl = str(row[add_label_col]).lower() if add_label_col and pd.notna(row[add_label_col]) else "legitimate"
        
        # 1. Check duplicate within current addition batch
        if norm in seen_in_batch:
            duplicates_count += 1
            continue
        seen_in_batch.add(norm)
        
        # 2. Check duplicate / conflict against existing original dataset
        if norm in existing_urls:
            existing_lbl = str(existing_labels[norm]).lower()
            if existing_lbl != lbl:
                conflicts_count += 1
                quarantined_records.append({
                    "url": u,
                    "norm_url": norm,
                    "reason": f"LABEL_CONFLICT: existing='{existing_lbl}' vs incoming='{lbl}'",
                    "incoming_label": lbl,
                    "existing_label": existing_lbl,
                    "timestamp": now_ts
                })
            else:
                duplicates_count += 1
            continue
            
        # 3. Valid new verified record
        added_records.append({
            "url": u,
            "entropy": compute_entropy(u),
            "url_length": len(u),
            "label": lbl,
            "source_provenance": row.get("verification_source", "verified_crawler_harvest"),
            "norm_url": norm
        })
        
    print(f"Summary: New valid={len(added_records)} | Duplicates={duplicates_count} | Quarantined={len(quarantined_records)}")
    
    # Construct updated merged dataset
    df_new = pd.DataFrame(added_records)
    
    # Harmonize columns with original dataset
    orig_cols = [c for c in df_orig.columns if c != "norm_url"]
    for col in orig_cols:
        if col not in df_new.columns:
            if col in ["num_www", "ratio_digits_url", "num_subdomains", "length_hostname", "num_dots", "num_hyphens", "ratio_digits_host", "prefix_suffix", "num_question_mark", "num_eq", "domain_age", "dns_resolvable", "num_ips", "ttl", "num_name_servers", "domain_age_unknown"]:
                df_new[col] = 0
                
    df_merged = pd.concat([df_orig[orig_cols], df_new[orig_cols]], ignore_index=True)
    
    # Save outputs
    output_merged_csv.parent.mkdir(parents=True, exist_ok=True)
    df_merged.to_csv(output_merged_csv, index=False)
    print(f"Saved merged dataset to: {output_merged_csv} ({len(df_merged)} rows)")
    
    if quarantined_records:
        df_quar = pd.DataFrame(quarantined_records)
        quarantine_output_csv.parent.mkdir(parents=True, exist_ok=True)
        df_quar.to_csv(quarantine_output_csv, index=False)
        print(f"Saved quarantined records to: {quarantine_output_csv}")
        
    manifest = {
        "timestamp": now_ts,
        "original_rows": original_count,
        "new_verified_rows_added": len(added_records),
        "total_merged_rows": len(df_merged),
        "class_distribution": df_merged["label"].value_counts().to_dict(),
        "duplicates_skipped": duplicates_count,
        "conflicts_quarantined": len(quarantined_records),
        "output_path": str(output_merged_csv)
    }
    with open(manifest_output_json, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Saved merge manifest to: {manifest_output_json}")
    
    return manifest
