"""PaddleOCR 3.x CPU adapter and normalized result parsing."""
import importlib.metadata
import numpy as np


def package_versions():
    """Return installed PaddleOCR/Paddle versions without failing if absent."""
    result = {}
    for package in ("paddleocr", "paddlepaddle"):
        try:
            result[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result[package] = "not installed"
    try:
        import paddle
        result["paddle_runtime"] = paddle.__version__
        result["gpu_compiled"] = bool(paddle.is_compiled_with_cuda())
    except Exception as exc:
        result["paddle_runtime"] = f"unavailable: {type(exc).__name__}: {exc}"
    return result


def create_ocr_engine(language="en", ocr_version="PP-OCRv5", cpu_threads=4):
    """Create a PaddleOCR 3.x pipeline explicitly pinned to CPU."""
    from paddleocr import PaddleOCR
    return PaddleOCR(lang=language, ocr_version=ocr_version, device="cpu",
                     cpu_threads=cpu_threads, use_doc_orientation_classify=False,
                     use_doc_unwarping=False, use_textline_orientation=False, enable_mkldnn=False)


def _result_dict(result):
    """Convert a PaddleOCR result object/dict to its result payload."""
    if isinstance(result, dict):
        payload = result.get("res", result)
    else:
        payload = getattr(result, "json", {})
        if callable(payload):
            payload = payload()
        if isinstance(payload, dict):
            payload = payload.get("res", payload)
    return payload if isinstance(payload, dict) else {}


def parse_ocr_output(results):
    """Normalize PaddleOCR 3.x predict results to text, confidence, polygon rows."""
    detections = []
    for result in results or []:
        payload = _result_dict(result)
        texts = payload.get("rec_texts", []) or []
        scores = payload.get("rec_scores", []) or []
        polygons = payload.get("rec_polys", payload.get("dt_polys", [])) or []
        for index, text in enumerate(texts):
            score = float(scores[index]) if index < len(scores) else None
            polygon = polygons[index] if index < len(polygons) else None
            if hasattr(polygon, "tolist"):
                polygon = polygon.tolist()
            detections.append(
                {"text": str(text), "confidence": score, "bounding_box": polygon})
    return detections


def predict_image(engine, image):
    """Run a single RGB Pillow image through PaddleOCR 3.x and normalize it."""
    results = engine.predict(np.asarray(image.convert("RGB")))
    return parse_ocr_output(results)
