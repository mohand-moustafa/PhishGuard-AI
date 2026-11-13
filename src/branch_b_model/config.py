"""Configuration and target-language model registry for CPU OCR."""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# PaddleOCR PP-OCRv5 model language selectors documented by the project.
# Each selector maps to a recognition model; they are NOT one joint model.
LANGUAGE_MODELS = {
    "English": "en",
    "Arabic": "ar",
    "Chinese (Simplified)": "ch",
    "Japanese": "japan",
    "Russian": "ru",
    "Korean": "korean",
    "German": "de",
    "French": "fr",
    "Indonesian": "id",
    "Norwegian": "no",
    "Romanian": "ro",
    "Turkish": "tr",
    "Spanish": "es",
    "Thai": "th",
}


@dataclass
class OCRConfig:
    """Runtime options; defaults are conservative and CPU-only."""
    output_dir: Path
    default_language: str = "en"
    ocr_version: str = "PP-OCRv5"
    confidence_threshold: float = 0.4
    above_fold_ratio: float = 0.40
    crop_mode: str = "full"  # select only after reviewing sample experiments
    use_preprocessing: bool = False
    use_grayscale: bool = False
    use_denoising: bool = False
    threshold_value: Optional[int] = None
    resize_max_side: Optional[int] = None
    resume: bool = True
    retry_failed: bool = True
    use_gpu: bool = False
    cpu_threads: int = 4
    keywords: tuple = ("login", "log in", "sign in", "password", "verify", "verification",
                       "account", "bank", "card", "credit card", "debit card", "security", "update",
                       "confirm", "payment", "billing", "suspended", "locked", "urgent", "otp", "code", "identity")

    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        if self.use_gpu:
            raise ValueError(
                "This notebook defaults to CPU; use_gpu must be False.")
        if not 0 <= self.confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be between 0 and 1")
        if not 0 < self.above_fold_ratio <= 1:
            raise ValueError("above_fold_ratio must be in (0, 1]")
        if self.crop_mode not in {"full", "above_fold"}:
            raise ValueError("crop_mode must be 'full' or 'above_fold'")
        if self.default_language not in set(LANGUAGE_MODELS.values()):
            raise ValueError(
                f"Unsupported language selector: {self.default_language}")
        if self.threshold_value is not None and not 0 <= int(self.threshold_value) <= 255:
            raise ValueError("threshold_value must be between 0 and 255")
