# PhishGuard AI

A multimodal AI system that detects phishing websites in real time by
combining three signals: the URL/domain itself, the page's HTML/DOM
structure, and its visual appearance (screenshot-based analysis). Built as
a graduation project for **Egypt Digital Pioneers Initiative (DEPI)** - AI &
Data Science track, Microsoft ML Engineer specialization.

> **Status: Phase 1 - Data Collection.** No model training has started yet.
> See `docs/PROJECT_PLAN.md` for the full roadmap and current week.

## The idea

A URL is checked from three angles at once:

- **Branch A - URL & HTML analysis**: lexical features of the URL,
  domain age, SSL certificate info, and the page's HTML/DOM (forms, hidden
  iframes, external scripts, redirects).
- **Branch B - Visual analysis**: a screenshot of the page is analyzed with
  OCR, logo detection, and a Vision Transformer to catch pages that visually
  impersonate a known brand even when the domain doesn't match.
- **Fusion layer**: combines both branches into one decision + confidence
  score, explained in plain language (via SHAP/Grad-CAM + an LLM
  explanation layer) and surfaced live through a browser extension.

Full architecture, data pipeline, weekly timeline, and team role split:
**[`docs/PROJECT_PLAN.md`](docs/PROJECT_PLAN.md)**.

## Team

| Name | Role |
|---|---|
| Mohand Moustafa | TBD |
| Mohamed Walid | TBD |
| Noureldin Mahmoud | TBD |
| Mahmoud Didamon | TBD |
| Sama Tarek | TBD |
| Martina safwat | TBD |

## Project structure

```
phishguard-ai/
├── data/                   # git-ignored - see data/README.md for access
├── notebooks/              # exploratory analysis (Jupyter)
├── src/
│   ├── data_collection/    # scrapers/downloaders (OpenPhish, Tranco, PhiUSIIL...)
│   ├── feature_extraction/ # URL + HTML + WHOIS/RDAP + SSL features
│   ├── branch_a_model/     # XGBoost training + leakage audits
│   ├── branch_b_model/     # OCR, logo detection, Vision Transformer
│   ├── fusion/             # meta-classifier combining both branches
│   ├── explainability/     # SHAP, Grad-CAM, LLM explanation layer
│   └── api/                # FastAPI backend serving predictions
├── extension/               # Chrome/Edge browser extension (Manifest V3)
├── models/                  # trained model artifacts - git-ignored
├── tests/
└── docs/                    # project plan, notes, presentation material
```

## Setup

```bash
git clone <repo-url>
cd phishguard-ai
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # fill in any keys you have
```

## Contributing (team workflow)

- Never commit directly to `main`. Branch off, then open a Pull Request.
- Branch naming: `feature/<short-description>`, e.g. `feature/rdap-domain-age`.
- Data and trained models are **not** committed to Git (too large, and they
  change too often) - see `data/README.md` for where they actually live and
  how to sync them.
- Keep `requirements.txt` up to date whenever you add a new library.

## License

Academic project - DEPI graduation initiative, [year].
