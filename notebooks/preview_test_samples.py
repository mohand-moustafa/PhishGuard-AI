import os
import sys
import json
import random

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import torch
from PIL import Image
from transformers import ViTImageProcessor, ViTForImageClassification
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT_DIR = r"E:\Depi\Phishing and Legitimate Websites"
MODEL_DIR = os.path.join(PROJECT_DIR, "outputs", "vit_phishguard")
TEST_DIR = os.path.join(PROJECT_DIR, "cv_work", "clean_dataset", "test")

print(f"Loading best saved model from: {MODEL_DIR} on CPU...")
device = "cpu"
proc = ViTImageProcessor.from_pretrained(MODEL_DIR)
model = ViTForImageClassification.from_pretrained(MODEL_DIR).to(device).eval()

# Select samples: 4 legitimate, 4 phishing
legit_dir = os.path.join(TEST_DIR, "legitimate")
phish_dir = os.path.join(TEST_DIR, "phishing")

random.seed(42)
legit_files = [os.path.join(legit_dir, f) for f in os.listdir(legit_dir) if f.lower().endswith((".png", ".jpg", ".jpeg"))]
phish_files = [os.path.join(phish_dir, f) for f in os.listdir(phish_dir) if f.lower().endswith((".png", ".jpg", ".jpeg"))]

sample_legit = random.sample(legit_files, 4)
sample_phish = random.sample(phish_files, 4)
samples = [(p, "legitimate") for p in sample_legit] + [(p, "phishing") for p in sample_phish]
random.shuffle(samples)

results = []
fig, axes = plt.subplots(2, 4, figsize=(16, 8))
axes = axes.ravel()

for i, (path, true_label) in enumerate(samples):
    img = Image.open(path).convert("RGB")
    inputs = proc(images=img, return_tensors="pt")["pixel_values"].to(device)
    
    with torch.no_grad():
        logits = model(pixel_values=inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]
        p_phish = probs[1].item()
        p_legit = probs[0].item()
        
    pred_label = "phishing" if p_phish >= 0.5 else "legitimate"
    is_correct = (pred_label == true_label)
    confidence = p_phish if pred_label == "phishing" else p_legit
    
    results.append({
        "filename": os.path.basename(path),
        "true_label": true_label,
        "pred_label": pred_label,
        "confidence": confidence,
        "is_correct": is_correct
    })
    
    # Plot image
    ax = axes[i]
    ax.imshow(img)
    color = "green" if is_correct else "red"
    status_sym = "[CORRECT]" if is_correct else "[WRONG]"
    title = f"True: {true_label}\nPred: {pred_label} ({confidence*100:.1f}%)\nStatus: {status_sym}"
    ax.set_title(title, color=color, fontsize=10, fontweight="bold")
    ax.axis("off")

plt.tight_layout()
preview_save_path = os.path.join(MODEL_DIR, "test_predictions_preview.png")
plt.savefig(preview_save_path, dpi=150, bbox_inches="tight")
plt.close()

print(f"\nPreview image saved to: {preview_save_path}")
print("\n" + "=" * 70)
print(f"{'Filename':<35} | {'True':<10} | {'Predicted':<10} | {'Conf %':<8} | {'Status'}")
print("=" * 70)
for r in results:
    stat = "CORRECT" if r["is_correct"] else "WRONG"
    print(f"{r['filename'][:33]:<35} | {r['true_label']:<10} | {r['pred_label']:<10} | {r['confidence']*100:6.2f}%  | {stat}")
print("=" * 70)

# Save results JSON
with open(os.path.join(MODEL_DIR, "sample_preview_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
