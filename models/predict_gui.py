import os
import torch
from PIL import Image
from transformers import ViTImageProcessor, ViTForImageClassification

# Get current folder path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

class PhishDetector:
    def __init__(self, model_folder=None):
        if model_folder is None:
            model_folder = CURRENT_DIR
            
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"[Loading Model] Using device: {self.device}")
        
        # Load processor and model directly from this folder
        self.processor = ViTImageProcessor.from_pretrained(model_folder)
        self.model = ViTForImageClassification.from_pretrained(model_folder).to(self.device).eval()
        print("[Ready] Model loaded successfully!")

    def predict(self, image_path, threshold=0.5):
        """
        Analyzes a screenshot image and returns phishing verdict.
        """
        img = Image.open(image_path).convert("RGB")
        inputs = self.processor(images=img, return_tensors="pt")["pixel_values"].to(self.device)
        
        with torch.no_grad():
            logits = self.model(pixel_values=inputs).logits
            probs = torch.softmax(logits, dim=-1)[0]
            p_legit = float(probs[0].item())
            p_phish = float(probs[1].item())
            
        is_phishing = (p_phish >= threshold)
        label = "phishing" if is_phishing else "legitimate"
        confidence = p_phish if is_phishing else p_legit
        
        return {
            "label": label,
            "confidence": round(confidence * 100, 2),
            "is_phishing": is_phishing,
            "probabilities": {
                "legitimate": round(p_legit * 100, 2),
                "phishing": round(p_phish * 100, 2)
            }
        }

if __name__ == "__main__":
    # Test example
    detector = PhishDetector()
    print("PhishDetector class is ready to be imported into any GUI!")
