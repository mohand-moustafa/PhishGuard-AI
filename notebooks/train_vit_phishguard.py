import os
import sys
import random
import json
import time

# Reconfigure stdout/stderr for Windows console to handle UTF-8 cleanly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torchvision import datasets
from transformers import (
    ViTImageProcessor,
    ViTForImageClassification,
    get_cosine_schedule_with_warmup
)
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, ConfusionMatrixDisplay, roc_curve, classification_report
)
import mlflow

# Change working directory to project folder
PROJECT_DIR = r"E:\Depi\Phishing and Legitimate Websites"
os.chdir(PROJECT_DIR)

print("=" * 60)
print("[START] Starting PhishGuard ViT Training on GPU")
print("=" * 60)

# 1. Device Setup
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Device: {DEVICE}")
if DEVICE == "cuda":
    print(f"GPU Name: {torch.cuda.get_device_name(0)}")
    print(f"Total VRAM: {round(torch.cuda.get_device_properties(0).total_memory / 1e9, 2)} GB")
    torch.cuda.empty_cache()
else:
    print("[WARNING] GPU not available, running on CPU!")

# 2. Configuration
CFG = dict(
    train_dir="cv_work/clean_dataset/train",
    val_dir="cv_work/clean_dataset/val",
    test_dir="cv_work/clean_dataset/test",
    external_dir="data/phish_iris",
    model_name="google/vit-base-patch16-224",
    out_dir="outputs/vit_phishguard",
    num_workers=0,  # 0 on Windows
    seed=42,
    fp16=True,
    p1=dict(epochs=3, lr=1e-3, bs=32),
    p2=dict(epochs=10, lr=2e-5, bs=32, last_n_blocks=4, wd=0.01, warmup=0.1),
    es=dict(patience=3, min_delta=5e-4)
)

os.makedirs(CFG["out_dir"], exist_ok=True)
random.seed(CFG["seed"])
np.random.seed(CFG["seed"])
torch.manual_seed(CFG["seed"])
if DEVICE == "cuda":
    torch.cuda.manual_seed_all(CFG["seed"])

# 3. Processor & Dataset
print("\n[1/6] Loading ViT Image Processor & Datasets...")
processor = ViTImageProcessor.from_pretrained(CFG["model_name"])

class ViTFolder(datasets.ImageFolder):
    def __init__(self, root, processor):
        super().__init__(root)
        self.processor = processor

    def __getitem__(self, index):
        img, y = super().__getitem__(index)
        pixel_values = self.processor(images=img.convert("RGB"), return_tensors="pt")["pixel_values"][0]
        return pixel_values, y

def loader(root, bs, shuffle):
    ds = ViTFolder(root, processor)
    return ds, DataLoader(ds, batch_size=bs, shuffle=shuffle, num_workers=CFG["num_workers"], pin_memory=(DEVICE == "cuda"))

train_ds, train_dl1 = loader(CFG["train_dir"], CFG["p1"]["bs"], True)
_,        train_dl2 = loader(CFG["train_dir"], CFG["p2"]["bs"], True)
val_ds,   val_dl    = loader(CFG["val_dir"], 64, False)
test_ds,  test_dl   = loader(CFG["test_dir"], 64, False)

for name, ds in [("train", train_ds), ("val", val_ds), ("test", test_ds)]:
    c = np.bincount(ds.targets, minlength=2)
    print(f"  {name:5s} | Total: {len(ds):6d} | Legitimate: {c[0]:5d} | Phishing: {c[1]:5d}")

# 4. Model Initialization
print("\n[2/6] Initializing ViT Model...")
model = ViTForImageClassification.from_pretrained(
    CFG["model_name"],
    num_labels=2,
    id2label={0: "legitimate", 1: "phishing"},
    label2id={"legitimate": 0, "phishing": 1},
    ignore_mismatched_sizes=True
)

# Proper initialization for the new classifier head to prevent FP16 underflow/denormals
nn.init.trunc_normal_(model.classifier.weight, std=0.02)
nn.init.zeros_(model.classifier.bias)
model = model.to(DEVICE)

print(f"  Total parameters: {sum(p.numel() for p in model.parameters()):,}")

cnt = np.bincount(train_ds.targets, minlength=2)
class_w = torch.tensor(cnt.sum() / (2 * cnt), dtype=torch.float).to(DEVICE)
criterion = nn.CrossEntropyLoss(weight=class_w)
print(f"  Class weights: legitimate={class_w[0]:.4f}, phishing={class_w[1]:.4f}")

# 5. Helper Functions
@torch.no_grad()
def predict(model, dl):
    model.eval()
    P, Y, L, n = [], [], 0.0, 0
    ce = nn.CrossEntropyLoss(reduction="sum")
    for x, y in dl:
        x, y = x.to(DEVICE), y.to(DEVICE)
        lg = model(pixel_values=x).logits
        L += ce(lg, y).item()
        n += len(y)
        P.append(torch.softmax(lg, -1)[:, 1].cpu())
        Y.append(y.cpu())
    return torch.cat(P).numpy(), torch.cat(Y).numpy(), L / n

def compute_metrics(y, p, thr=0.5):
    pr = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pr, labels=[0, 1]).ravel()
    return dict(
        accuracy=accuracy_score(y, pr),
        precision=precision_score(y, pr, zero_division=0),
        recall=recall_score(y, pr, zero_division=0),
        f1=f1_score(y, pr, zero_division=0),
        roc_auc=roc_auc_score(y, p) if len(set(y)) > 1 else float("nan"),
        tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp)
    )

def set_trainable(model, head_only, last_n=0):
    for p in model.parameters():
        p.requires_grad = False
    for p in model.classifier.parameters():
        p.requires_grad = True
    if not head_only:
        for blk in model.vit.encoder.layer[-last_n:]:
            for p in blk.parameters():
                p.requires_grad = True
        for p in model.vit.layernorm.parameters():
            p.requires_grad = True
    return sum(p.numel() for p in model.parameters() if p.requires_grad)

HIST = []
STEP = 0
BEST = dict(f1=0.0, phase="", epoch=0)

def run_phase(name, model, dl, pc, head_only):
    global STEP
    ntr = set_trainable(model, head_only, pc.get("last_n_blocks", 0))
    print(f"\n[{name.upper()}] Trainable parameters: {ntr:,}")
    mlflow.log_param(f"{name}_trainable_params", ntr)
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=pc["lr"], weight_decay=pc.get("wd", 0.0))
    total = pc["epochs"] * len(dl)
    sched = get_cosine_schedule_with_warmup(opt, int(pc.get("warmup", 0.0) * total), total)
    use_amp = (DEVICE == "cuda" and CFG.get("fp16", False))
    scaler = torch.cuda.amp.GradScaler(enabled=use_amp)
    bad = 0

    for ep in range(pc["epochs"]):
        start_time = time.time()
        model.train()
        run, n = 0.0, 0
        total_batches = len(dl)
        for i, (x, y) in enumerate(dl, 1):
            x, y = x.to(DEVICE), y.to(DEVICE)
            opt.zero_grad()
            with torch.autocast(DEVICE, enabled=use_amp):
                loss = criterion(model(pixel_values=x).logits, y)
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            nn.utils.clip_grad_norm_(params, 1.0)
            scaler.step(opt)
            scaler.update()
            sched.step()
            run += loss.item() * len(y)
            n += len(y)

            if i % 50 == 0 or i == total_batches:
                elapsed = time.time() - start_time
                print(f"  [{name} | Ep {ep+1:02d}/{pc['epochs']:02d}] Batch {i:4d}/{total_batches:4d} "
                      f"| Current Loss: {loss.item():.4f} | Time: {elapsed:.1f}s")

        p, yv, vl = predict(model, val_dl)
        m = compute_metrics(yv, p)
        ep_time = time.time() - start_time
        row = dict(
            phase=name, epoch=ep + 1, train_loss=run / n, val_loss=vl,
            val_f1=m["f1"], val_precision=m["precision"], val_recall=m["recall"],
            val_auc=m["roc_auc"], val_acc=m["accuracy"], time_sec=round(ep_time, 1)
        )
        HIST.append(row)
        STEP += 1
        mlflow.log_metrics({f"{name}/{k}": v for k, v in row.items() if isinstance(v, float)}, step=STEP)

        print(f"\n  [METRICS] [{name}] Ep {ep+1:02d}/{pc['epochs']:02d} | Train Loss: {row['train_loss']:.4f} "
              f"| Val Loss: {vl:.4f} | Val F1: {m['f1']:.4f} | Val AUC: {m['roc_auc']:.4f} | Time: {ep_time:.1f}s")

        if m["f1"] > BEST["f1"] + CFG["es"]["min_delta"]:
            BEST.update(f1=m["f1"], phase=name, epoch=ep + 1)
            bad = 0
            model.save_pretrained(CFG["out_dir"], safe_serialization=True)
            torch.save(model.state_dict(), os.path.join(CFG["out_dir"], "best_model.pt"))
            print(f"     * [New Best Saved] F1: {m['f1']:.4f}")
        else:
            bad += 1
            if bad >= CFG["es"]["patience"]:
                print(f"     [EARLY STOPPING] triggered at epoch {ep+1}")
                break

# 6. Training Execution
print("\n[3/6] Starting Phase 1: Classifier Head Training...")
processor.save_pretrained(CFG["out_dir"])
try:
    mlflow.end_run()
except Exception:
    pass

run = mlflow.start_run(run_name="vit_two_phase")
mlflow.log_params({
    "model": CFG["model_name"], "seed": CFG["seed"],
    "train_n": len(train_ds), "val_n": len(val_ds), "test_n": len(test_ds),
    **{f"p1_{k}": v for k, v in CFG["p1"].items()},
    **{f"p2_{k}": v for k, v in CFG["p2"].items()},
    **{f"es_{k}": v for k, v in CFG["es"].items()}
})

run_phase("phase1", model, train_dl1, CFG["p1"], head_only=True)
print(f"\nPhase 1 finished. Best so far: {BEST}")

print("\n[4/6] Starting Phase 2: Full Fine-Tuning (Last 4 Blocks)...")
model = ViTForImageClassification.from_pretrained(CFG["out_dir"]).to(DEVICE)
run_phase("phase2", model, train_dl2, CFG["p2"], head_only=False)
print(f"\nPhase 2 finished. Overall Best: {BEST}")

# 7. Final Evaluation on Test Set
print("\n[5/6] Evaluating Best Model on Test Set...")
best_model = ViTForImageClassification.from_pretrained(CFG["out_dir"]).to(DEVICE)
p, y, _ = predict(best_model, test_dl)
M = compute_metrics(y, p)

print("\n" + "=" * 50)
print("TEST SET RESULTS:")
print("=" * 50)
for k, v in M.items():
    print(f"  {k:12s}: {round(v, 4) if isinstance(v, float) else v}")
print("\nClassification Report:")
print(classification_report(y, (p >= 0.5).astype(int), target_names=["legitimate", "phishing"], digits=4))

# Plots
fig, ax = plt.subplots(1, 2, figsize=(11, 4))
ConfusionMatrixDisplay(confusion_matrix(y, (p >= 0.5).astype(int)), display_labels=["legit", "phish"]).plot(ax=ax[0], colorbar=False)
fpr, tpr, _ = roc_curve(y, p)
ax[1].plot(fpr, tpr, label=f"AUC={M['roc_auc']:.4f}")
ax[1].plot([0, 1], [0, 1], "--", c="gray")
ax[1].set_xlabel("FPR")
ax[1].set_ylabel("TPR")
ax[1].legend()
ax[1].set_title("ROC (test)")
plt.tight_layout()
plots_path = os.path.join(CFG["out_dir"], "test_plots.png")
plt.savefig(plots_path, dpi=150)
plt.close()
print(f"Plots saved to: {plots_path}")

# Save artifacts
mlflow.log_metrics({f"test_{k}": v for k, v in M.items()})
mlflow.log_params({"best_phase": BEST["phase"], "best_epoch": BEST["epoch"]})
metrics_path = os.path.join(CFG["out_dir"], "test_metrics.json")
json.dump({"test": M, "best": BEST}, open(metrics_path, "w"), indent=2)

history_path = os.path.join(CFG["out_dir"], "training_history.csv")
pd.DataFrame(HIST).to_csv(history_path, index=False)

for f in ["config.json", "preprocessor_config.json", "model.safetensors", "test_metrics.json", "test_plots.png", "training_history.csv"]:
    fp = os.path.join(CFG["out_dir"], f)
    if os.path.exists(fp):
        mlflow.log_artifact(fp)

# External validation check
print("\n[6/6] External Validation Check...")
if os.path.exists(CFG["external_dir"]):
    ext_ds, ext_dl = loader(CFG["external_dir"], 64, False)
    assert ext_ds.classes == ["legitimate", "phishing"], ext_ds.classes
    pe, ye, _ = predict(best_model, ext_dl)
    ME = compute_metrics(ye, pe)
    print(f"Phish-Iris n={len(ext_ds)}")
    for k, v in ME.items():
        print(f"  {k}: {round(v, 4) if isinstance(v, float) else v}")
    mlflow.log_metrics({f"ext_{k}": v for k, v in ME.items()})
    json.dump(ME, open(os.path.join(CFG["out_dir"], "external_phish_iris_metrics.json"), "w"), indent=2)
    mlflow.log_artifact(os.path.join(CFG["out_dir"], "external_phish_iris_metrics.json"))
else:
    print(f"  External dataset '{CFG['external_dir']}' not found, skipping.")

mlflow.end_run()

print("\n" + "=" * 60)
print("[COMPLETED] ALL PHASES COMPLETED SUCCESSFULLY!")
print(f"Saved artifacts in: {CFG['out_dir']}")
print("=" * 60)
