import spacy
from spacy.language import Language
from spacy.cli import download

# We define a custom NLP function to extract IP addresses using Regex within SpaCy.
# SpaCy's default model is great for finding People, Dates, and Organizations, 
# but we need to teach it what an IP address looks like using an "Entity Ruler".

def setup_nlp_pipeline():
    """Loads the SpaCy model and adds custom rules for network logs."""
    try:
        # Load the small English core model
        nlp = spacy.load("en_core_web_sm")
        print("Successfully loaded SpaCy model 'en_core_web_sm'.")
    except OSError:
        # If the user hasn't downloaded the model yet, we download it automatically
        print("Downloading SpaCy 'en_core_web_sm' model. This may take a minute...")
        download("en_core_web_sm")
        nlp = spacy.load("en_core_web_sm")
    
    # Check if we already added our custom IP rule to avoid errors on reload
    if "ip_entity_ruler" not in nlp.pipe_names:
        # Create an EntityRuler to find specific text patterns
        ruler = nlp.add_pipe("entity_ruler", name="ip_entity_ruler", before="ner")
        
        # Define the Regex pattern for an IPv4 address
        patterns = [
            {
                "label": "IP_ADDRESS", 
                "pattern": [{"TEXT": {"REGEX": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"}}]
            },
            {
                "label": "PROTOCOL",
                "pattern": [{"LOWER": "ssh2"}]
            }
        ]
        ruler.add_patterns(patterns)
        
    return nlp

# Initialize our custom NLP engine
nlp_engine = setup_nlp_pipeline()

def extract_entities_from_log(message: str) -> dict:
    """
    Takes a raw text message, processes it through the NLP engine, 
    and returns a dictionary of found entities.
    """
    # Process the text
    doc = nlp_engine(message)
    
    extracted_data = {}
    
    # Loop through the recognized entities in the text
    for ent in doc.ents:
        # Save the entity label (e.g., 'IP_ADDRESS') and the actual text (e.g., '45.33.22.11')
        extracted_data[ent.label_] = ent.text
        
    return extracted_data

# --- Quick Test ---
if __name__ == "__main__":
    test_log = "Failed password for root from 45.33.22.11 port 22 ssh2 at 10:00 AM"
    print(f"Testing NLP Parser on: '{test_log}'")
    entities = extract_entities_from_log(test_log)
    print(f"Extracted Entities: {entities}")