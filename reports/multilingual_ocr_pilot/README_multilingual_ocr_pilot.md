# Multilingual OCR Pilot — Branch B

## Overview

This folder contains the outputs of the Branch B OCR and text-analysis pilot for the PhishGuard AI project.

The pilot processes **48 images** across **11 OCR languages** using **PaddleOCR PP-OCRv5 on CPU**. It extracts OCR text, cleans the text, detects multilingual security-related keywords, and produces structured OCR features for handoff to the ML integration teammate.

> **Important:** These are pilot results for 48 images, not OCR results for the full cleaned dataset.

## Main deliverable

### `merged_multilingual_ocr_features.csv`

This is the main file to share with the ML teammate.

- Shape: **48 rows × 28 columns**
- 48 unique image IDs
- No duplicate or missing image IDs
- No missing values after final validation
- Includes the image label, OCR metadata/features, and multilingual keyword features

Example loading code:

```python
import pandas as pd

features_path = (
    "reports/multilingual_ocr_pilot/"
    "merged_multilingual_ocr_features.csv"
)

ocr_features = pd.read_csv(features_path)

print("Shape:", ocr_features.shape)
print("Unique images:", ocr_features["image_id"].nunique())
print(ocr_features.head())
```

## Output files

| File | Description |
|---|---|
| `multilingual_ocr_results.csv` | Per-image OCR output and metadata, including extracted text, detections, confidence information, language, and processing time |
| `multilingual_keyword_results.csv` | Per-image multilingual keyword matches and category-level features |
| `merged_multilingual_ocr_features.csv` | Main merged feature table for ML integration |
| `language_performance_summary.csv` | OCR processing-time summary grouped by language |
| `manual_ocr_review.csv` | Manual review status, text-quality assessment, and notes for pilot images |
| `manual_review_by_language.csv` | Manual review counts grouped by language, label, and quality |
| `manual_review_quality_summary.csv` | Counts of manually reviewed images by OCR text quality |
| `manual_review_label_summary.csv` | Label distribution among manually reviewed images |
| `multilingual_ocr_quality_report.md` | Human-readable summary of the pilot and its quality limitations |

## Feature guide

The merged CSV includes the original OCR feature columns and multilingual keyword features.

Important columns include:

| Column | Meaning |
|---|---|
| `image_id` | Unique image identifier |
| `label` | Existing dataset label (phishing or legitimate) |
| `ocr_model_language` | OCR language/model code used for the image |
| `raw_text` | Text returned by OCR before later text processing |
| `filtered_text` | Text after the pipeline's OCR filtering stage |
| `cleaned_text` | Cleaned OCR text from the OCR pipeline |
| `ocr_keyword_count` | Keyword count from the original OCR pipeline keyword configuration |
| `multilingual_total_matches` | Total matches from the multilingual keyword dictionaries |
| `multilingual_matched_keywords` | Text of the matched multilingual keywords; empty when no keyword matched |
| `multilingual_<category>_count` | Number of matches for a keyword category |
| `multilingual_<category>_present` | Binary indicator: 1 if the category has at least one match, otherwise 0 |

The five multilingual categories are:

1. `authentication`
2. `credentials`
3. `account_security`
4. `financial`
5. `urgency`

For example, `multilingual_credentials_count` is the number of credential-related keyword matches, while `multilingual_credentials_present` indicates whether at least one such match was found.

### Important distinction

`ocr_keyword_count` and `multilingual_total_matches` are not interchangeable:

- `ocr_keyword_count` comes from the original OCR pipeline keyword configuration.
- `multilingual_total_matches` comes from the multilingual dictionaries used in this pilot.

## Languages represented in the pilot

The pilot includes these 11 language codes:

`ar`, `de`, `en`, `es`, `fr`, `id`, `no`, `ro`, `ru`, `th`, `tr`

The language codes correspond to the OCR model-language settings used by the project. Some non-English languages have only one or two pilot examples, so their results should be treated as preliminary.

## Manual quality review

A qualitative manual review was completed for **15 of the 48 pilot images**:

- Good: 9
- Partial: 6
- Pending: 33

The reviewed sample included both phishing and legitimate labels. The review is qualitative and is **not** a measured OCR accuracy score. A larger representative sample with ground-truth text transcriptions would be needed to calculate quantitative OCR metrics such as character error rate or word error rate.

## Integration notes for the ML teammate

1. Load `merged_multilingual_ocr_features.csv`.
2. Join it to the relevant image-level dataset using `image_id`.
3. Validate that IDs and labels align before using the features.
4. Select feature columns deliberately; do not use identifiers or raw text as numeric model inputs without an appropriate text-processing strategy.
5. Treat `label` as the target only if that matches the team's agreed training setup.
6. Keep the pilot scope in mind: these 48 rows are for pipeline validation and exploration, not a substitute for processing the full dataset.
7. Review possible data leakage and ensure any train/validation/test split is performed at the appropriate image or duplicate-group level.

Example feature selection:

```python
multilingual_feature_columns = [
    column
    for column in ocr_features.columns
    if column.startswith("multilingual_")
    and column.endswith(("_count", "_present"))
]

print(multilingual_feature_columns)
```

This example selects the numeric multilingual category features and excludes the matched-keyword text column.

## Known limitations

- The pilot contains 48 images only.
- Language representation is imbalanced; several languages have only one example.
- OCR quality varies by image, script, screenshot quality, and page layout.
- Some OCR outputs contain recognition errors, fragmented text, mixed-language content, or irrelevant page elements.
- Keyword matching is dictionary-based. A match is an exploratory signal, not proof that a page is phishing.
- No keyword match does not prove that a page is legitimate; it may reflect OCR errors, dictionary coverage, or language-specific tokenization.
- The manual review is partial and qualitative.
- Near-duplicate candidates identified during dataset auditing require appropriate review/splitting controls to reduce train/test leakage.

## Recommended handoff

Share these items with the ML teammate:

1. `merged_multilingual_ocr_features.csv` — main feature file.
2. `multilingual_ocr_quality_report.md` — quality and limitation summary.
3. `manual_ocr_review.csv` — detailed manual review notes.
4. The OCR notebook and relevant source modules from `src/branch_b_model/` — for reproducibility.

Before full model integration, agree on the full-dataset processing plan, feature selection, ID-join strategy, and train/validation/test split with the ML teammate.
