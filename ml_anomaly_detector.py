from transformers import pipeline
import torch
import warnings

# Suppress some harmless huggingface warnings to keep our terminal clean
warnings.filterwarnings("ignore")

print("Loading Hugging Face Zero-Shot Classifier (PyTorch backend)...")
print("This might take a minute on the first run to download the model.")

# We load a small, fast "DistilBERT" model configured for Natural Language Inference (NLI)
# We explicitly set framework="pt" to ensure it uses PyTorch.
classifier = pipeline(
    "zero-shot-classification", 
    model="typeform/distilbert-base-uncased-mnli", 
    framework="pt"
)

def detect_anomaly(log_message: str) -> dict:
    """
    Uses a pre-trained Hugging Face transformer to classify if a log is an attack.
    Returns a dictionary with the anomaly status and confidence score.
    """
    # We give the AI two categories to choose from
    candidate_labels = ["normal network traffic", "malicious cyber attack or failure"]
    
    # The model processes the text and returns probabilities for each label
    result = classifier(log_message, candidate_labels)
    
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