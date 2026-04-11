from transformers import pipeline
import warnings
import os

# Suppress harmless HuggingFace warnings
warnings.filterwarnings("ignore")

MODEL_NAME = os.getenv("ANOMALY_MODEL", "typeform/distilbert-base-uncased-mnli")

# Lazy singleton — model is NOT loaded at import time.
# It is created on the first call to detect_anomaly().
_classifier = None

def _get_classifier():
    """Load the classifier on first use (lazy init) to avoid crashing on startup."""
    global _classifier
    if _classifier is None:
        print(f"Loading Hugging Face Zero-Shot Classifier ({MODEL_NAME})...")
        print("This may take a minute on first run to download the model.")
        _classifier = pipeline(
            "zero-shot-classification",
            model=MODEL_NAME,
            framework="pt"
        )
        print("✅ Classifier loaded successfully.")
    return _classifier

def detect_anomaly(log_message: str) -> dict:
    """
    Uses a pre-trained Hugging Face transformer to classify if a log is an attack.
    Returns a dictionary with the anomaly status and confidence score.
    """
    # We give the AI two categories to choose from
    candidate_labels = ["normal network traffic", "malicious cyber attack or failure"]
    
    # The model processes the text and returns probabilities for each label
    result = _get_classifier()(log_message, candidate_labels)
    
    # Extract the scores (result["labels"] and result["scores"] are sorted highest to lowest)
    labels = result["labels"]
    scores = result["scores"]
    
    # Zip them into an easy-to-read dictionary
    classification = dict(zip(labels, scores))
    
    # Get the specific score for "malicious cyber attack or failure"
    attack_score = classification["malicious cyber attack or failure"]
    
    # We define our threshold: If the AI is more than 60% sure it's an attack, we flag it.
    is_anomaly = attack_score > 0.60
    
    return {
        "is_anomaly": bool(is_anomaly),
        "confidence_score": round(float(attack_score), 4),
        "full_scores": classification
    }

# --- Quick Test ---
if __name__ == "__main__":
    normal_log = "HTTP_GET request from 192.168.1.15 completed with status SUCCESS."
    attack_log = "Failed password for root from 45.33.22.11 port 22 ssh2"
    
    print("\nTesting Normal Log:")
    print(detect_anomaly(normal_log))
    
    print("\nTesting Attack Log:")
    print(detect_anomaly(attack_log))