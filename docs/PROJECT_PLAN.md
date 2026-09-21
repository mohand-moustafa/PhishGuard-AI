# Multimodal AI Phishing Detection — Full Project Plan

**Graduation Project — Digital Egypt Pioneers Initiative (DEPI) | AI & Data Science Track**
**Team Size: 4–5 Members | Duration: 3+ Months**

---

## 1. Project Overview

An end-to-end system that takes a URL as input and determines whether it is **phishing** or **legitimate**, by simultaneously analyzing three distinct data sources:

1. **The URL itself** (lexical and typosquatting analysis)
2. **The page's source code** (HTML/DOM analysis)
3. **The page's visual appearance** (screenshot → OCR + logo detection + vision model)

The final output is a **single decision, a confidence score, and a human-readable explanation** (in Arabic/English) of why the site was classified as it was — delivered live through a **browser extension**.

### Proposed Project Name
`PhishGuard AI`, `SentinelPhish`, or `TrustLens` — any name that conveys "real-time protection."

---

## 2. System Architecture (End-to-End Pipeline)

```
                          [URL is typed/opened in the browser]
                                      |
                        (Browser extension captures the URL)
                                      |
                        ---------------------------------
                        |                               |
                 [Fast Local Checks]            [Send to Backend API]
                (Simple typosquatting            (for deeper analysis,
                 rules run instantly,              when needed)
                 no server required)                    |
                                              -------------------------
                                              |                       |
                                       [Branch A: URL/HTML]   [Branch B: Visual]
                                              |                       |
                                    - Lexical features          - Crawler (Playwright)
                                    - WHOIS lookup                 opens the URL and
                                    - SSL certificate check        captures a screenshot
                                    - HTML/DOM parsing                    |
                                    - Typosquatting score        - OCR (extract on-page text)
                                    - JS/iframe analysis         - Logo detection (YOLO)
                                              |                  - Brand verification
                                       [XGBoost Model]           - Vision Transformer
                                              |                  (general visual classification)
                                              |                          |
                                              -------------------------
                                                          |
                                              [Fusion / Meta-Classifier]
                                        (combines both branches' outputs
                                              + logo-mismatch flag)
                                                          |
                                              [Final Decision + Confidence Score]
                                                          |
                                          [Explainability Layer: SHAP + LLM]
                                       "This page is suspicious because it
                                        displays a Microsoft logo on a
                                        mismatched domain, with a hidden
                                        login form."
                                                          |
                                          [Response returned to the extension]
                                                          |
                                          [Warning popup/banner shown to the user]
```

---

## 3. Phase 1: Data Collection — Weeks 1–3

### 3.1 Data Sources

| Source | Type | How to Obtain It |
|---|---|---|
| **PhishTank** (phishtank.org) | Daily-updated phishing URLs + free API | Free account registration → API key → daily CSV/JSON download |
| **OpenPhish** (openphish.com) | Similar feed, free community tier | Direct download from the site's community feed |
| **Tranco List** (tranco-list.eu) | Top one million legitimate sites (a more reliable alternative to Alexa) | Direct CSV download from the site |
| **UCI Phishing Dataset** | Ready-made dataset with pre-extracted features (~11,000 rows) | Kaggle / UCI Repository — useful as a quick baseline in week 1 |
| **Kaggle – Phishing Website Detector datasets** | Various collections including URLs and, occasionally, screenshots | Direct search on Kaggle |

**Proposed target**: 15,000–20,000 URLs (roughly balanced between phishing and legitimate) — a large enough sample to train robust models without an excessive collection timeline.

### 3.2 Building the Crawler (Data Engineering Team)

A Python script that performs the following for each URL in the list:

1. Opens the URL using **Playwright** (faster and more stable than Selenium)
2. Captures a **full-page screenshot** (not just the visible viewport)
3. Saves the full **HTML source code**
4. Extracts the **response headers** (SSL info, redirect chain)
5. Records the **final URL** after any redirects (important, since many phishing sites redirect)
6. Uses a short timeout (5–8 seconds) for unresponsive URLs, logging them as "unreachable" rather than halting the entire script

```
Proposed storage structure per URL:
/dataset
  /screenshots/{id}.png
  /html_raw/{id}.html
  /metadata.csv   -> columns: id, url, final_url, label, whois_age,
                      has_ssl, redirect_count, timestamp
```

**Key recommendation**: Run the crawler in small batches (100–200 URLs at a time) using async/multiprocessing, since opening thousands of URLs sequentially would take days. Use `asyncio` with Playwright's async API.

### 3.3 Labeling

- URLs from PhishTank/OpenPhish → label = 1 (phishing), assigned automatically
- URLs from the Tranco top-sites list → label = 0 (legitimate), assigned automatically
- **Important**: Perform a manual spot-check on a random sample (200–300 URLs) to catch mislabeled data, since some PhishTank entries may already be offline by the time the data is collected

---

## 4. Phase 2: Branch A — URL and HTML Analysis — Weeks 3–6

### 4.1 Lexical Features (Derived from the URL Text, Without Visiting It)

| Feature | Example |
|---|---|
| Total URL length | `len(url)` |
| Number of dots (subdomains) | `bank.secure.login.xyz.com` = 4 dots, suspicious |
| IP address used instead of a domain name | `http://192.168.1.1/login` |
| Presence of `@` in the URL | A common tactic used to hide the real domain |
| Number of hyphens in the domain | `paypal-secure-login.com` |
| Use of HTTPS or not | |
| Domain name length | Phishing domains are often longer than typical ones |
| Presence of suspicious keywords | `secure`, `verify`, `account`, `update`, `login` combined with an unfamiliar domain |

### 4.2 Typosquatting Detection (Key Contribution, Critically Important)

A simple and effective algorithm:

1. Build a list of the top 200–500 globally recognized domains (Google, Microsoft, PayPal, Facebook, Amazon, Egyptian banks, etc.)
2. For each new domain encountered, compute the **Levenshtein distance** between it and every entry in the list
3. If the distance is very small (1–2 characters) but the domain is not an exact match → a strong indicator of typosquatting
4. Add a **homoglyph substitution** check (character look-alike replacement, e.g., letters swapped for similar-looking digits): `o→0`, `l→1`, `i→l`, etc. This can be implemented with a simple mapping dictionary and regex

```python
# Simplified pseudocode example
from Levenshtein import distance
known_brands = ["google.com", "microsoft.com", "paypal.com", ...]

def typosquat_score(domain):
    scores = [distance(domain, brand) for brand in known_brands]
    min_dist = min(scores)
    if min_dist <= 2 and domain not in known_brands:
        return True, known_brands[scores.index(min_dist)]
    return False, None
```

### 4.3 WHOIS & SSL Features

- **Domain age**: via the `python-whois` library — phishing domains are typically less than a month old
- **SSL certificate**: Is there a valid certificate? Which certificate authority issued it? Free certificates (e.g., Let's Encrypt) are common in phishing sites because they are quick and free to obtain

### 4.4 HTML/DOM Features

Extracted from the page source captured by the crawler:

- Number of `<form>` tags, and whether any contain a `password` field
- Presence of hidden `<iframe>` elements (`display:none` or `width=0`)
- Number of external scripts and their sources
- Presence of JavaScript redirects (`window.location.href = ...`)
- Obfuscated JavaScript (abnormally encoded or complex code)

### 4.5 Model

**XGBoost** as the primary model over all the aggregated features (classic tabular data). It trains quickly, provides clear feature importance, and integrates easily with SHAP for later explainability.

---

## 5. Phase 3: Branch B — Visual Analysis Pipeline — Weeks 5–9

This is the most engineering-intensive branch, as agreed, and is split into four modules.

### 5.1 OCR — Extracting Text from the Screenshot

- Use **EasyOCR** or **Tesseract** (EasyOCR is easier to set up and performs well on both English and Arabic text)
- Goal: extract any visible text on the page (titles, buttons, alerts), even when the page is rendered entirely as an image — a common tactic phishing sites use to evade text-based filters

### 5.2 Logo Detection

- **Concept**: train or use a pretrained model to recognize the logos of well-known companies (Microsoft, Google, PayPal, Facebook, banks, etc.) within the screenshot
- **Practical approach**: use **YOLOv8** (relatively easy to train) and fine-tune it on a small dataset of these logos (50–100 images per logo can be collected from Google Images, or an existing dataset such as `Logo-2K+` or `FlickrLogos` can be used)
- **Faster alternative if time is limited**: use **CLIP** (from OpenAI) for zero-shot logo matching without training from scratch — feed it a reference logo image and the page image, and it returns a similarity score

### 5.3 Brand Verification (the Project's Key Differentiator)

Logic:
```
If logo detection reports: "Microsoft logo found on the page"
   AND the actual domain = "micr0soft-support.xyz"
   (i.e., not the official microsoft.com)
=> Raise a high-confidence Brand Mismatch flag
   (this is close to definitive evidence of phishing)
```

Build a **reference dictionary**: `{"microsoft": ["microsoft.com", "live.com", "office.com"], "google": ["google.com", "gmail.com"], ...}` and compare against it.

### 5.4 Vision Transformer (General Visual Classification)

- Use a **pretrained ViT** (from Hugging Face, e.g., `google/vit-base-patch16-224`) and apply **transfer learning** (fine-tuning on your labeled phishing/legitimate screenshots)
- This provides a "general design sense" — phishing pages often mimic well-known login page designs in ways that are visually detectable even without a clear logo

---

## 6. Phase 4: Fusion Layer — Weeks 9–10

Rather than a complex 5-model ensemble, start with something simpler and more robust:

**A lightweight meta-classifier (Logistic Regression or a light XGBoost model)** takes as input:
- Probability output from XGBoost (Branch A)
- Probability output from ViT (Branch B)
- Brand Mismatch flag (0 or 1) — weighted heavily, as it is a strong signal
- Typosquatting flag (0 or 1)

...and produces the final decision plus a confidence score. Simplicity is intentional here: it is easy to explain to the review committee and easy to debug when a specific case is misclassified.

**If time allows in the final month**: try adding LightGBM as a second model in Branch A and averaging it with XGBoost — a modest, low-risk improvement without the complexity of a full ensemble.

---

## 7. Phase 5: Explainability — Week 10–11

### 7.1 SHAP for XGBoost
Highlights which features most influenced the decision (e.g., "domain age contributed 40%").

### 7.2 Grad-CAM for the Vision Transformer
Produces a **heatmap** showing which part of the page the model focused on visually (e.g., the logo or the login form).

### 7.3 LLM Explanation Layer (a Key Value-Add)
Take all the extracted features and flags (brand mismatch, typosquatting, hidden iframe, etc.) and pass them as a prompt to an LLM (Claude API or any available API) to convert them into a clear sentence, for example:

> "This page is flagged as phishing with 92% confidence because it displays a Microsoft logo while its registered domain (`micr0soft-verify.xyz`) is not officially associated with Microsoft, and it contains a hidden login form along with a JavaScript-based redirect."

This is straightforward to implement (a single API call with a pre-built prompt) and significantly strengthens the demo in front of the committee, since it demonstrates genuine "understanding" rather than just a number.

---

## 8. Phase 6: Backend API — Weeks 8–11 (in Parallel with Other Phases)

- **FastAPI** (faster and simpler than Flask for ML serving, with built-in auto-documentation)
- Core endpoints:
  - `POST /analyze` → accepts a URL, runs the full pipeline, and returns the decision plus explanation
  - `GET /health` → confirms the server is running
- Trained models are saved as `.pkl` (XGBoost) and `.pt` or ONNX (ViT), and loaded once at server startup (not on every request, for performance)
- Use **MLflow** throughout training to log every experiment (accuracy, parameters, model version) — this is valuable for comparing model versions and demonstrates a professional working methodology to the review committee

---

## 9. Phase 7: Browser Extension — Weeks 11–13

### 9.1 Core Structure (Manifest V3 — required, since Chrome is deprecating V2)

```
extension/
  manifest.json
  background.js      -> captures the current URL, sends the request to the API
  content.js          -> controls the warning display within the page itself
  popup.html/js       -> the interface shown when the user clicks the extension icon
  icons/
```

### 9.2 Operational Flow

1. The user opens any website
2. `background.js` automatically captures the current URL (via the `chrome.tabs` API)
3. **Fast local check first**: a lightweight typosquatting check runs in local JavaScript (without waiting for the server) — an immediate warning is shown if there is a strong indication
4. In parallel, a request is sent to the backend API for full analysis (URL + HTML, with a screenshot request if needed)
5. If the result is "phishing" → a **clear red warning banner** is displayed over the page (injected via `content.js`) explaining the reason (from the LLM explanation layer)
6. If the user clicks the extension icon → a popup shows further details (score, contributing features, etc.)

### 9.3 Demo Recommendation

Prepare a **simple mock phishing page built by the team** (not a real one, for ethical reasons, but realistic enough) to use in the live demo in front of the committee. This ensures the demo works reliably, rather than depending on a live phishing URL that could go offline unexpectedly during the presentation.

---

## 10. Phase 8: Deployment — Week 12–13

- **Backend**: deploy to **Azure App Service** or **Azure ML Endpoint** (a good fit given the Microsoft-track training, and it demonstrates practical use of the tools covered in the program)
- **Extension**: does not need to be published on the Chrome Web Store (which requires a review period) — running it as an "unpacked extension" during the demo, or providing a simple installer, is sufficient

---

## 11. Phase 9: Evaluation Metrics — Throughout the Project

Metrics to track and document:

| Metric | Why It Matters |
|---|---|
| **Precision** | Minimizes false positives (a legitimate site misclassified as phishing frustrates users) |
| **Recall** | Minimizes false negatives (a missed phishing site represents a real security risk) |
| **F1-Score** | Balances the two above |
| **ROC-AUC** | Evaluates overall model performance independent of threshold choice |
| **Confusion Matrix** | Should be included in the presentation to visually convey model performance |
| **Testing on entirely new sites** | Collect 50–100 new Egyptian/Arabic legitimate sites not present in the training data, to confirm the model doesn't misclassify them (an important false-positive test) |

---

## 12. Role Distribution Across the Project (Team of 4–5)

| Member | Core Responsibility | Active Weeks |
|---|---|---|
| 1 – Data Engineer | Crawler development, data collection, labeling, WHOIS/SSL extraction | Weeks 1–6 |
| 2 – ML Engineer (Structured Data) | Feature engineering, XGBoost, typosquatting algorithm | Weeks 3–9 |
| 3 – CV Engineer | OCR, logo detection (YOLO/CLIP), Vision Transformer | Weeks 5–10 |
| 4 – Backend/Extension Developer | FastAPI, fusion layer, full browser extension | Weeks 8–13 |
| 5 (if available) – Explainability/Documentation | SHAP, Grad-CAM, LLM explanation layer, presentation and demo prep | Weeks 10–13 (supports the rest of the team throughout) |

**Note**: For a team of 4, one of the three technical members takes on Explainability/Documentation as an addition to their core role.

---

## 13. Detailed Timeline (13+ Weeks)

| Week | Key Tasks |
|---|---|
| 1 | Finalize project scope, set up working environment (repo, Azure account, API access), begin downloading PhishTank/OpenPhish/Tranco data |
| 2 | Build the crawler (Playwright), collect the first batch of screenshots + HTML |
| 3 | Continue data collection up to 15,000–20,000 URLs; begin manual spot-checking of labels |
| 4 | Extract lexical, WHOIS, and SSL features; begin the typosquatting algorithm |
| 5 | Complete HTML/DOM features; first baseline XGBoost model |
| 6 | Tune XGBoost (hyperparameter optimization); begin collecting logo images for logo detection |
| 7 | Set up the OCR pipeline; begin fine-tuning YOLO/CLIP for logo detection |
| 8 | Begin fine-tuning the Vision Transformer on screenshots; first version of the FastAPI backend |
| 9 | Build brand verification logic; connect logo detection to domain checking |
| 10 | Build the fusion/meta-classifier; begin SHAP + Grad-CAM |
| 11 | LLM explanation layer; set up the core browser extension (manifest, background, content scripts) |
| 12 | Connect the extension to the backend fully; end-to-end testing; begin deployment on Azure |
| 13 | Comprehensive testing (false-positive tests), final improvements, prepare presentation and demo scenario |
| 14+ (if 3+ months available) | Buffer time for unforeseen issues, plus UI/UX improvements to the extension and dashboard |

---

## 14. Key Differentiators for the Review Committee (Summary)

1. ✅ **Genuinely multimodal** (not just URLs, and not just images — both combined through clear logic)
2. ✅ **Brand verification** — intelligent logic linking logo detection with domain accuracy
3. ✅ **A real live demo** via a fully functional browser extension during the presentation
4. ✅ **Human-readable explainability** (not just a percentage) through the LLM layer
5. ✅ **Documented professional methodology** (MLflow tracking for every experiment)
6. ✅ **False-positive testing** on new Egyptian/Arabic sites — demonstrates awareness of real model limitations, not just favorable metrics

---

## 15. Anticipated Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Data collection takes longer than expected | Start with the ready-made UCI dataset as a baseline from week 1, while collecting original data in parallel |
| Logo detection is not accurate enough within the available time | Use CLIP (zero-shot) as a faster alternative to training YOLO from scratch |
| High false-positive rate on new Arabic/Egyptian sites | Reserve sufficient time in the final month for testing and fine-tuning on Arabic examples |
| Insufficient time to develop the extension | Start its core structure early (week 8), even without full backend integration, and build it incrementally |
| The server fails during the live demo | Prepare an "offline demo" (a recorded video) as backup alongside the live demo |
