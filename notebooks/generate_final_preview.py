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

print(f"Loading final best model from: {MODEL_DIR}...")
device = "cuda" if torch.cuda.is_available() else "cpu"
proc = ViTImageProcessor.from_pretrained(MODEL_DIR)
model = ViTForImageClassification.from_pretrained(MODEL_DIR).to(device).eval()

legit_dir = os.path.join(TEST_DIR, "legitimate")
phish_dir = os.path.join(TEST_DIR, "phishing")

random.seed(123)
legit_files = [os.path.join(legit_dir, f) for f in os.listdir(legit_dir) if f.lower().endswith((".png", ".jpg", ".jpeg"))]
phish_files = [os.path.join(phish_dir, f) for f in os.listdir(phish_dir) if f.lower().endswith((".png", ".jpg", ".jpeg"))]

# Sample 5 legitimate and 5 phishing
sample_legit = random.sample(legit_files, 5)
sample_phish = random.sample(phish_files, 5)
samples = [(p, "legitimate") for p in sample_legit] + [(p, "phishing") for p in sample_phish]
random.shuffle(samples)

results = []
fig, axes = plt.subplots(2, 5, figsize=(20, 8))
axes = axes.ravel()

for i, (path, true_label) in enumerate(samples):
    img = Image.open(path).convert("RGB")
    inputs = proc(images=img, return_tensors="pt")["pixel_values"].to(device)
    
    with torch.no_grad():
        logits = model(pixel_values=inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]
        p_phish = float(probs[1].item())
        p_legit = float(probs[0].item())
        
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
    
    ax = axes[i]
    ax.imshow(img)
    color = "#2ecc71" if is_correct else "#e74c3c"
    status_sym = "[CORRECT]" if is_correct else "[WRONG]"
    title = f"True: {true_label.upper()}\nPred: {pred_label.upper()} ({confidence*100:.1f}%)\n{status_sym}"
    ax.set_title(title, color=color, fontsize=11, fontweight="bold", pad=8)
    ax.axis("off")

plt.tight_layout()
final_preview_path = os.path.join(MODEL_DIR, "final_test_predictions_preview.png")
plt.savefig(final_preview_path, dpi=160, bbox_inches="tight")
plt.close()

print(f"Final preview image saved to: {final_preview_path}")
print("\n" + "=" * 75)
print(f"{'Filename':<35} | {'Actual':<10} | {'Predicted':<10} | {'Conf %':<8} | {'Status'}")
print("=" * 75)
for r in results:
    stat = "CORRECT [OK]" if r["is_correct"] else "WRONG   [X]"
    print(f"{r['filename'][:33]:<35} | {r['true_label']:<10} | {r['pred_label']:<10} | {r['confidence']*100:6.2f}%  | {stat}")
print("=" * 75)

with open(os.path.join(MODEL_DIR, "final_sample_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
