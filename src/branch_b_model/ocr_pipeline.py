"""Incremental, resumable OCR processing and report generation."""
import json, os, re, time
from pathlib import Path
import pandas as pd
from .config import OCRConfig
from .image_preprocessing import load_rgb, crop_above_fold, apply_configured_preprocessing
from .ocr_engine import create_ocr_engine, predict_image
from .text_analysis import clean_text, find_keywords, keyword_counts

class OCRPipeline:
    """One-image-at-a-time CPU OCR runner with durable per-image checkpoints."""
    def __init__(self, config, engine_factory=create_ocr_engine):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir = self.output_dir / "checkpoints"
        self.checkpoint_dir.mkdir(exist_ok=True)
        self.engine_factory = engine_factory
        self.engines = {}
        self.results_jsonl = self.output_dir / "ocr_results.jsonl"
        self.results_csv = self.output_dir / "ocr_results.csv"
        self.summary_csv = self.output_dir / "ocr_image_summary.csv"
        self.errors_csv = self.output_dir / "ocr_errors.csv"
        self.features_csv = self.output_dir / "ocr_features.csv"
        self.keyword_csv = self.output_dir / "keyword_frequency.csv"
        self.evaluation_json = self.output_dir / "ocr_evaluation_summary.json"

    def engine(self, language):
        """Cache one model instance for each explicitly selected language."""
        if language not in self.engines:
            self.engines[language] = self.engine_factory(language, self.config.ocr_version, self.config.cpu_threads)
        return self.engines[language]

    def process_one(self, row, language=None, crop_mode=None, preprocessing=None):
        """Process one manifest row; return a JSON-safe record and elapsed seconds."""
        started = time.perf_counter()
        image_path = Path(str(row["resolved_path"]))
        language = language or self.config.default_language
        crop_mode = crop_mode or self.config.crop_mode
        preprocessing = self.config.use_preprocessing if preprocessing is None else bool(preprocessing)
        raw_detections, error, width, height, crop_meta = [], None, None, None, {}
        status = "failed"
        try:
            image = load_rgb(image_path)
            width, height = image.size
            if crop_mode == "above_fold":
                image, crop_meta = crop_above_fold(image, self.config.above_fold_ratio)
            else:
                crop_meta = {"original_width": width, "original_height": height,
                             "crop_x": 0, "crop_y": 0, "crop_width": width,
                             "crop_height": height, "crop_ratio": 1.0}
            image = apply_configured_preprocessing(image, preprocessing, self.config.resize_max_side,
                grayscale=self.config.use_grayscale, denoise=self.config.use_denoising,
                threshold=self.config.threshold_value)
            raw_detections = predict_image(self.engine(language), image)
            status = "success"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        elapsed = time.perf_counter() - started
        filtered = [d for d in raw_detections if d.get("confidence") is not None and d["confidence"] >= self.config.confidence_threshold]
        raw_text = "\n".join(d["text"] for d in raw_detections)
        filtered_text = "\n".join(d["text"] for d in filtered)
        cleaned = clean_text(filtered_text)
        matches = find_keywords(cleaned, self.config.keywords)
        counts = keyword_counts(matches)
        preprocessing_applied = bool(preprocessing or self.config.use_grayscale or
                                     self.config.use_denoising or self.config.threshold_value is not None)
        record = {"image_id": str(row["image_id"]), "path": str(row["resolved_path"]),
            "label": str(row["label"]), "raw_text": raw_text, "filtered_text": filtered_text, "cleaned_text": cleaned,
            "raw_detections": raw_detections, "filtered_detections": filtered,
            "detected_text_lines": len(filtered), "confidence_scores": [d["confidence"] for d in filtered],
            "bounding_boxes": [d["bounding_box"] for d in filtered],
            "matched_keywords": matches, "keyword_counts": counts, "keyword_count": len(matches),
            "image_width": width, "image_height": height, "crop_mode": crop_mode,
            "crop_metadata": crop_meta, "preprocessing_applied": preprocessing_applied,
            "contrast_sharpen_applied": preprocessing,
            "ocr_model_language": language, "ocr_version": self.config.ocr_version,
            "confidence_threshold": self.config.confidence_threshold, "resize_max_side": self.config.resize_max_side,
            "grayscale_applied": self.config.use_grayscale, "denoising_applied": self.config.use_denoising,
            "threshold_value": self.config.threshold_value,
            "processing_time_seconds": elapsed, "ocr_status": status, "error_message": error}
        return record

    def _checkpoint_path(self, image_id):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(image_id))
        return self.checkpoint_dir / f"{safe}.json"

    def _write_record(self, record):
        """Persist one per-image checkpoint immediately for safe resume."""
        cp = self._checkpoint_path(record["image_id"])
        temp = cp.with_suffix(".json.tmp")
        temp.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        os.replace(temp, cp)

    def _load_records(self):
        records = []
        for checkpoint in sorted(self.checkpoint_dir.glob("*.json")):
            try:
                records.append(json.loads(checkpoint.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return records

    def _rebuild_outputs(self):
        """Write consistent reusable outputs from the small JSON checkpoint records."""
        records = self._load_records()
        if not records:
            return
        tmp_jsonl = self.results_jsonl.with_suffix(".jsonl.tmp")
        with tmp_jsonl.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        os.replace(tmp_jsonl, self.results_jsonl)
        flat = []
        for r in records:
            flat.append({k: json.dumps(r[k], ensure_ascii=False) if isinstance(r.get(k), (dict, list)) else r.get(k)
                         for k in ("image_id", "path", "label", "raw_text", "cleaned_text", "raw_detections",
                           "filtered_detections", "filtered_text", "detected_text_lines", "confidence_scores", "bounding_boxes",
                           "matched_keywords", "keyword_counts", "keyword_count", "image_width", "image_height",
                           "crop_mode", "crop_metadata", "preprocessing_applied", "contrast_sharpen_applied", "ocr_model_language", "ocr_version",
                           "confidence_threshold", "resize_max_side", "grayscale_applied", "denoising_applied",
                           "threshold_value", "processing_time_seconds", "ocr_status", "error_message")})
        frame = pd.DataFrame(flat)
        for path in (self.results_csv, self.summary_csv):
            temporary = path.with_suffix(path.suffix + ".tmp")
            frame.to_csv(temporary, index=False, encoding="utf-8-sig")
            os.replace(temporary, path)
        errors = frame.loc[frame.ocr_status != "success"]
        errors.to_csv(self.errors_csv, index=False, encoding="utf-8-sig")
        self._write_keyword_frequency(records)
        self._write_features(records)

    def _write_keyword_frequency(self, records):
        from collections import Counter
        total = Counter()
        for r in records:
            total.update(r.get("keyword_counts", {}))
        pd.DataFrame([{"keyword": k, "occurrences": v} for k,v in total.most_common()],
                     columns=["keyword", "occurrences"]).to_csv(self.keyword_csv, index=False, encoding="utf-8-sig")

    def _write_features(self, records):
        rows=[]
        for r in records:
            text=r.get("cleaned_text", "")
            words=re.findall(r"[^\W_]+(?:['’][^\W_]+)?", text, flags=re.UNICODE)
            scores=r.get("confidence_scores", [])
            counts=r.get("keyword_counts", {})
            row={"image_id":r["image_id"], "label":r["label"], "ocr_text_length":len(text),
                 "ocr_word_count":len(words), "ocr_line_count":r.get("detected_text_lines",0),
                 "ocr_mean_confidence":sum(scores)/len(scores) if scores else None,
                 "ocr_keyword_count":r.get("keyword_count",0),
                 "ocr_processing_time_seconds":r.get("processing_time_seconds"), "ocr_status":r.get("ocr_status")}
            for key in ("login","password","verify","account","bank","card"):
                row[f"ocr_has_{key}"]=int(counts.get(key,0)>0)
            rows.append(row)
        pd.DataFrame(rows).to_csv(self.features_csv,index=False,encoding="utf-8-sig")

    def run(self, manifest, limit=None, force=False, progress=True, language_by_image_id=None):
        """Run validated rows one at a time with per-image restart checkpoints."""
        from tqdm.auto import tqdm
        rows=manifest.head(int(limit)) if limit is not None else manifest
        existing={str(r["image_id"]):r for r in self._load_records()}
        language_by_image_id = language_by_image_id or {}
        iterator=rows.to_dict("records")
        if progress: iterator=tqdm(iterator, total=len(iterator), desc="OCR")
        for row in iterator:
            image_id=str(row["image_id"])
            saved=existing.get(image_id)
            selected_language = language_by_image_id.get(image_id, self.config.default_language)
            same_settings = saved and all(saved.get(key) == value for key, value in {
                "ocr_model_language": selected_language,
                "ocr_version": self.config.ocr_version,
                "crop_mode": self.config.crop_mode,
                "contrast_sharpen_applied": self.config.use_preprocessing,
                "confidence_threshold": self.config.confidence_threshold,
                "resize_max_side": self.config.resize_max_side,
                "grayscale_applied": self.config.use_grayscale,
                "denoising_applied": self.config.use_denoising,
                "threshold_value": self.config.threshold_value,
            }.items())
            if self.config.resume and not force and saved and same_settings:
                if saved.get("ocr_status") == "success" or not self.config.retry_failed:
                    continue
            record=self.process_one(row, language=selected_language)
            self._write_record(record)
            existing[image_id]=record
        self._rebuild_outputs()
        results=pd.DataFrame(self._load_records())
        self.write_evaluation_summary(results)
        return results

    def write_evaluation_summary(self, results):
        """Persist operational performance only; these are not accuracy metrics."""
        attempted=len(results)
        success=int((results["ocr_status"]=="success").sum()) if attempted else 0
        failed=attempted-success
        times=pd.to_numeric(results.get("processing_time_seconds", pd.Series(dtype=float)), errors="coerce").dropna()
        summary={"images_in_results":attempted,"successfully_processed":success,"failed_images":failed,
            "success_rate_percent":100*success/attempted if attempted else None,
            "total_processing_time_seconds":float(times.sum()) if len(times) else 0.0,
            "average_processing_time_seconds":float(times.mean()) if len(times) else None,
            "median_processing_time_seconds":float(times.median()) if len(times) else None,
            "minimum_processing_time_seconds":float(times.min()) if len(times) else None,
            "maximum_processing_time_seconds":float(times.max()) if len(times) else None,
            "images_per_minute":60*len(times)/times.sum() if len(times) and times.sum()>0 else None,
            "recognition_accuracy":None,"accuracy_note":"No ground-truth OCR transcripts were provided; accuracy is not measured."}
        self.evaluation_json.write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding="utf-8")
        return summary
