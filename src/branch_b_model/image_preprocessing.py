"""Non-destructive image variants used for controlled OCR experiments."""
from PIL import Image, ImageEnhance, ImageFilter

def load_rgb(path):
    """Load one image into an independent RGB Pillow image."""
    with Image.open(path) as image:
        image.load()
        return image.convert("RGB")

def resize_preserving_aspect(image, max_side=1600):
    """Downscale only when needed; never distort or overwrite source pixels."""
    if max_side is None or max(image.size) <= max_side:
        return image.copy()
    scale = max_side / max(image.size)
    size = (max(1, round(image.width * scale)), max(1, round(image.height * scale)))
    return image.resize(size, Image.Resampling.LANCZOS)

def crop_above_fold(image, ratio=0.40):
    """Return top crop and source/crop geometry metadata."""
    if not 0 < ratio <= 1:
        raise ValueError("ratio must be in (0, 1]")
    width, height = image.size
    crop_height = max(1, min(height, round(height * ratio)))
    return image.crop((0, 0, width, crop_height)), {
        "original_width": width, "original_height": height, "crop_x": 0, "crop_y": 0,
        "crop_width": width, "crop_height": crop_height, "crop_ratio": ratio}

def make_variants(image, above_fold_ratio=0.40, resize_max_side=1600):
    """Build the six requested variants for a sample comparison."""
    original = image.convert("RGB")
    resized = resize_preserving_aspect(original, resize_max_side)
    gray = original.convert("L").convert("RGB")
    contrast = ImageEnhance.Contrast(original).enhance(1.25)
    crop, _ = crop_above_fold(original, above_fold_ratio)
    crop_processed = ImageEnhance.Sharpness(ImageEnhance.Contrast(crop).enhance(1.12)).enhance(1.08)
    return {"original": original, "resized": resized, "grayscale": gray,
            "contrast_enhanced": contrast, "above_fold": crop,
            "above_fold_preprocessed": crop_processed}

def apply_configured_preprocessing(image, enabled=False, max_side=None,
                                   grayscale=False, denoise=False, threshold=None):
    """Apply optional resize, grayscale, mild enhancement, denoise, and threshold."""
    result = resize_preserving_aspect(image.convert("RGB"), max_side)
    if grayscale:
        result = result.convert("L").convert("RGB")
    if enabled:
        result = ImageEnhance.Contrast(result).enhance(1.12)
        result = ImageEnhance.Sharpness(result).enhance(1.08)
    if denoise:
        result = result.filter(ImageFilter.MedianFilter(size=3))
    if threshold is not None:
        if not 0 <= int(threshold) <= 255:
            raise ValueError("threshold must be between 0 and 255")
        gray = result.convert("L")
        result = gray.point(lambda value: 255 if value >= int(threshold) else 0).convert("RGB")
    return result
