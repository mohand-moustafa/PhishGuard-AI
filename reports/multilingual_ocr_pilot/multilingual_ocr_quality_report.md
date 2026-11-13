# Multilingual OCR - Manual Quality Review Report

## 1. Overview

This report summarizes the manual quality assessment of the
multilingual OCR pilot conducted for the PhishGuard AI project.

- Total pilot images: 48
- Manually reviewed images: 15
- Pending images: 33
- Languages represented in reviewed sample: 11
- OCR model: PP-OCRv5
- Execution environment: CPU

## 2. Manual Review Results

| Quality | Images | Percentage |
|---|---:|---:|
| Good | 9 | 60.0% |
| Partial | 6 | 40.0% |
| Total | 15 | 100% |

Good indicates that the main visible text was extracted clearly.
Partial indicates that useful text was extracted, but noticeable
recognition errors, fragmentation, or ordering issues were observed.

## 3. Label Distribution

| Label | Images |
|---|---:|
| Phishing | 8 |
| Legitimate | 7 |

## 4. Language Coverage

- ar: 1 image(s)
- de: 1 image(s)
- en: 4 image(s)
- es: 1 image(s)
- fr: 2 image(s)
- id: 1 image(s)
- no: 1 image(s)
- ro: 1 image(s)
- ru: 1 image(s)
- th: 1 image(s)
- tr: 1 image(s)

The reviewed sample covers 11 languages.
English has the largest number of reviewed examples. Most other
languages have only one reviewed example.

## 5. Observed OCR Limitations

The manual review identified the following issues:

- Recognition errors in some characters and words.
- Fragmented text and imperfect reading order.
- Mixed-language content within some screenshots.
- Difficulty recognizing some non-Latin scripts and noisy text.
- Some extracted content may be incomplete or contain irrelevant page elements.

## 6. Evaluation Limitations

This is a qualitative manual review of 15 selected images from the
48-image multilingual pilot.

The sample is not a random or statistically representative sample.
Therefore, the percentages above must not be interpreted as overall
OCR accuracy, phishing detection accuracy, or general performance
across all supported languages.

The remaining 33 images were not manually reviewed.

## 7. Conclusion

The pilot demonstrates that the OCR pipeline can extract useful
website text across multiple languages.

However, extraction quality varies by image and language.
Further evaluation with larger, balanced language-specific samples
and ground-truth transcriptions would be required for a quantitative
OCR accuracy assessment.