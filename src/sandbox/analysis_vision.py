"""Screenshot/DOM evidence fusion and offline, explicitly configured visual models."""
from __future__ import annotations

import base64
import binascii
from functools import lru_cache
from heapq import nlargest
import io
import json
import os
from pathlib import Path
import struct
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from src.branch_b_model.text_analysis import clean_text, find_keywords

MODEL_LOCK = Lock()
CONTROL_WORDS = ("login", "log in", "sign in", "password", "verify", "submit", "continue")


def _image(encoded: str):
    from PIL import Image

    if not isinstance(encoded, str) or len(encoded) > 8_000_000:
        raise ValueError("screenshot exceeds encoded size budget")
    data = base64.b64decode(encoded, validate=True)
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("invalid viewport PNG")
    width, height = struct.unpack(">II", data[16:24])
    if not width or not height or max(width, height) > 2048 or width * height > 3_000_000:
        raise ValueError("viewport pixel budget exceeded")
    with Image.open(io.BytesIO(data), formats=["PNG"]) as image:
        return image.convert("RGB")


def _box(x: float, y: float, width: float, height: float) -> dict:
    return dict(x=round(x), y=round(y), width=round(width), height=round(height))


def _overlap(bbox: dict, other: dict) -> float:
    """Fraction of the measured visual region lying inside a DOM rectangle."""
    area = bbox["width"] * bbox["height"]
    if area <= 0:
        return 0
    w = min(bbox["x"] + bbox["width"], other["x"] + other["width"]) - max(bbox["x"], other["x"])
    h = min(bbox["y"] + bbox["height"], other["y"] + other["height"]) - max(bbox["y"], other["y"])
    return max(0, w) * max(0, h) / area


def _regions_at(bbox: dict, regions: list[dict]) -> dict:
    visible, receivers = [], []
    for region in regions:
        b = region["bbox"]
        overlap = _overlap(bbox, b)
        if region.get("offscreen") or overlap < 0.65:
            continue
        if region.get("hidden"):
            if region.get("intercepts") and region.get("receives_pointer"):
                receivers.append(region)
        else:
            visible.append((-overlap, b["width"] * b["height"], region["id"], region))
    owners = [item[-1] for item in sorted(visible, key=lambda i: i[:3])[:6]]
    covering = [r["id"] for r in receivers if r.get("document_id") and any(
        o.get("document_id") == r["document_id"] and o["selector"] in r["intercepts"] for o in owners
    ) and _overlap(bbox, r.get("visual_evidence_bbox") or r["bbox"]) >= 0.65]
    return {"element_ids": [r["id"] for r in owners], "occluding_receiver_ids": covering[:6]}


def _contours(image, regions: list[dict]) -> list[dict]:
    import cv2
    import numpy as np

    intensity = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2GRAY)
    factor = min(1.0, 768 / max(image.size))
    if factor < 1:
        intensity = cv2.resize(intensity, (max(1, round(image.width * factor)), max(1, round(image.height * factor))),
                               interpolation=cv2.INTER_AREA)
    edges = cv2.Canny(intensity, 65, 150)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    # Select a bounded number of control-sized contours before doing DOM joins.
    rectangles = (cv2.boundingRect(c) for c in contours)
    boxes = nlargest(120, (b for b in rectangles if 32 * factor <= b[2] <= edges.shape[1] * 0.95
                           and 15 * factor <= b[3] <= edges.shape[0] * 0.35), key=lambda b: b[2] * b[3])
    result = []
    for x, y, w, h in boxes:
        box = _box(x / factor, y / factor, w / factor, h / factor)
        result.append({"bbox": box, **_regions_at(box, regions)})
    return result


@lru_cache(maxsize=1)
def _ocr_engine():
    from rapidocr_onnxruntime import RapidOCR

    # The wheel contains PP-OCR ONNX weights. No model download or remote endpoint.
    return RapidOCR(intra_op_num_threads=1, inter_op_num_threads=1, max_side_len=960)


def _ocr(image, regions: list[dict]) -> list[dict]:
    import numpy as np

    # RapidOCR expects OpenCV BGR arrays. Keep inference concurrency bounded.
    results, _ = _ocr_engine()(np.asarray(image)[:, :, ::-1].copy(), use_cls=False)
    lines = []
    for polygon, label, score in (results or [])[:160]:
        if float(score) < 0.55:
            continue
        xs, ys = zip(*polygon)
        bbox = _box(min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
        text = clean_text(str(label)[:160])
        lines.append({"text": text, "confidence": round(float(score), 3), "bbox": bbox,
                      "keywords": [r["keyword"] for r in find_keywords(text, CONTROL_WORDS)],
                      **_regions_at(bbox, regions)})
    return lines


@lru_cache(maxsize=1)
def _logo_model(folder: Path):
    import cv2

    labels = json.loads((folder / "brands.json").read_text(encoding="utf-8"))
    if not isinstance(labels, list) or not (1 <= len(labels) <= 128):
        raise ValueError("brands.json must list one record per YOLO class")
    for row in labels:
        if (not isinstance(row.get("brand"), str) or not row["brand"].strip()
                or not isinstance(row.get("domains"), list) or not row["domains"]
                or any(not isinstance(d, str) or not d.strip() for d in row["domains"])):
            raise ValueError("invalid brand register")
    return cv2.dnn.readNetFromONNX(str(folder / "logos.onnx")), labels


@lru_cache(maxsize=1)
def _clip_model(folder: Path):
    from transformers import CLIPModel, CLIPProcessor

    args = {"local_files_only": True}
    model = CLIPModel.from_pretrained(str(folder), use_safetensors=True, **args).eval()
    return model, CLIPProcessor.from_pretrained(str(folder), **args)


def _verify_logo(image, brand: str, folder: Path) -> float:
    import torch

    model, processor = _clip_model(folder)
    inputs = processor(text=[f"the {brand} brand logo", "a generic interface icon or unrelated image"],
                       images=image, return_tensors="pt", padding=True)
    with torch.inference_mode():
        return float(model(**inputs).logits_per_image.softmax(dim=-1)[0, 0])


def _logos(image, url: str, regions: list[dict], folder: Path, statuses: dict) -> list[dict]:
    """YOLOv8 detect ONNX export at 640x640 with raw class scores (no embedded NMS)."""
    import cv2
    import numpy as np

    net, labels = _logo_model(folder)
    statuses["yolo"] = "available"
    ratio = min(640 / image.width, 640 / image.height)
    w, h = round(image.width * ratio), round(image.height * ratio)
    frame = np.full((640, 640, 3), 114, dtype="uint8")
    left, top = (640 - w) // 2, (640 - h) // 2
    frame[top:top+h, left:left+w] = cv2.resize(np.asarray(image), (w, h))
    net.setInput(cv2.dnn.blobFromImage(frame, 1 / 255.0))
    out = net.forward()
    if out.ndim != 3 or out.shape[:2] != (1, 4 + len(labels)):
        raise ValueError("YOLO ONNX output does not match registry")
    predictions = out[0].T
    scores = predictions[:, 4:].max(axis=1)
    likely = np.flatnonzero(scores >= 0.65)
    likely = likely[np.argsort(scores[likely])[::-1][:128]]
    boxes, ids, confidences = [], [], []
    for index in likely:
        cx, cy, bw, bh = predictions[index, :4]
        x1 = max(0, round(float(cx - bw/2 - left) / ratio))
        y1 = max(0, round(float(cy - bh/2 - top) / ratio))
        x2 = min(image.width, round(float(cx + bw/2 - left) / ratio))
        y2 = min(image.height, round(float(cy + bh/2 - top) / ratio))
        if x2 <= x1 or y2 <= y1:
            continue
        boxes.append([x1, y1, x2-x1, y2-y1])
        ids.append(int(predictions[index, 4:].argmax()))
        confidences.append(float(scores[index]))

    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    found = []
    for i in np.asarray(cv2.dnn.NMSBoxes(boxes, confidences, 0.65, 0.45)).flatten()[:8]:
        x, y, w, h = boxes[i]
        box = _box(x, y, w, h)
        brand = labels[ids[i]]
        official = any(host == domain or host.endswith("." + domain)
                       for domain in (d.strip(".").lower() for d in brand["domains"]))
        clip_score = None
        if (folder / "clip").is_dir():
            try:
                clip_score = _verify_logo(image.crop((x, y, x+w, y+h)), brand["brand"], folder / "clip")
                statuses["clip"] = "available"
            except (ImportError, OSError, RuntimeError, ValueError):
                statuses["clip"] = "unavailable"
        found.append({"brand": brand["brand"], "bbox": box, "confidence": confidences[i],
                      "clip_similarity": clip_score, "domain_mismatch": not official,
                      **_regions_at(box, regions)})
    return found


class PhishGuardVisionAnalyzer:
    def analyze(self, raw: dict) -> dict[str, Any]:
        """Set image_status to browser_error_document when Chromium owns the viewport.

        The original screenshot remains available as evidence of the capture failure.
        invalid_or_unsupported identifies an artifact the pixel decoder could not read.
        """
        regions = [r for r in raw.get("regions", [])[:360] if r.get("bbox") and r.get("id")]
        result = {"backends": {"pixels": "unavailable", "ocr": "unavailable",
                                "yolo": "unconfigured", "clip": "unconfigured"},
                  "ocr_lines": [], "segments": [], "brands": [],
                  "password_regions": [r["id"] for r in regions if r.get("input_type") == "password"],
                  "form_regions": [r["id"] for r in regions if r.get("tag") == "form"],
                  "visible_login_forms": [r["id"] for r in regions if r.get("tag") == "form"
                                          and r.get("credential") and not r.get("hidden") and not r.get("offscreen")],
                  "changes": [{"action_id": a.get("id"), "element_id": a.get("element_id"),
                               "bbox": a["changed_bbox"]} for a in raw.get("interactions", [])
                              if a.get("changed_bbox")]}
        if not (encoded := raw.get("screenshots", {}).get("viewport")):
            return result
        readiness = raw.get("coverage", {}).get("render_readiness", {})
        if readiness.get("browser_error_document") or (raw.get("final_url") or "").startswith("chrome-error:"):
            result["image_status"] = "browser_error_document"
            result["backends"] = dict.fromkeys(result["backends"], "not_run")
            return result
        try:
            image = _image(encoded)
        except (ImportError, ValueError, OSError, binascii.Error):
            result["image_status"] = "invalid_or_unsupported"
            return result
        backends = result["backends"]
        try:
            result["segments"] = _contours(image, regions)
            backends["pixels"] = "available"
        except (ImportError, RuntimeError):
            pass
        # Some inference engines retain mutable buffers. Serialize use across jobs.
        with MODEL_LOCK:
            try:
                result["ocr_lines"] = _ocr(image, regions)
                backends["ocr"] = "available"
            except (ImportError, OSError, RuntimeError, ValueError):
                pass
            if folder := os.environ.get("PHISHGUARD_BRAND_MODELS"):
                try:
                    result["brands"] = _logos(image, raw.get("final_url") or raw.get("url", ""),
                                              regions, Path(folder).resolve(), backends)
                except Exception as exc:
                    # Optional runtime/model errors must not discard DOM and interaction evidence.
                    backends["yolo"] = f"unavailable ({type(exc).__name__})"
        return result
