# Data

This folder is git-ignored (raw and processed data are too large for Git and
change too often). Nothing here is committed except this README.

## Where the data actually lives

Shared Google Drive folder: **[ضيفوا اللينك هنا بعد ما تعملوا الفولدر المشترك]**

Everyone should download into `data/raw/` locally - the folder structure on
disk should mirror the Drive folder so paths in scripts stay consistent for
everyone.

## Sources used so far

| Source | Type | Access method | Notes |
|---|---|---|---|
| OpenPhish (community feed) | phishing URLs | `https://openphish.com/feed.txt`, no registration | ~300-500 live URLs per pull, changes constantly - pull repeatedly and accumulate |
| Tranco List | legitimate domains | `https://tranco-list.eu/top-1m.csv.zip` | Academic alternative to Alexa Rank |
| PhishTank | phishing URLs | registration currently **closed** (as of this project) | fallback: `https://data.phishtank.com/data/online-valid.csv` without a key (slower refresh) |
| UCI PhiUSIIL Dataset (id=967) | both | `ucimlrepo.fetch_ucirepo(id=967)` | 235,795 rows, ready-made features - see `docs/phiusiil_audit_notes.md` before training on it |

## Known issues / gotchas

- PhiUSIIL label convention is the **opposite** of ours: `1 = legitimate`,
  `0 = phishing`. Flip it before merging with our own data.
- PhiUSIIL contains leakage features (`URLSimilarityIndex`,
  `TLDLegitimateProb`, `URLCharProb`) - drop them before training. Run
  `src/branch_a_model/phiusiil_audit.py` first.
- Our own scraped legitimate URLs are currently homepages only
  (`https://domain.com`), while phishing URLs have paths - this creates a
  length-based shortcut the model can cheat with. Needs fixing before the
  data is used for real training (see project plan, "Risks" section).

## File naming convention

- `data/raw/<source>_<YYYY-MM-DD>.csv` - a raw pull, never edited after saving
- `data/processed/featured_dataset_<version>.csv` - after feature extraction
