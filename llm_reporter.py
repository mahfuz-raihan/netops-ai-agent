import ollama

def generate_incident_report(log_data: dict) -> str:
    """
    Takes a flagged network log and uses a local LLM via Ollama 
    to generate a plain-English cybersecurity incident report.
    """
    print(f"🧠 Prompting Local LLM for analysis of IP: {log_data.get('ip_address')}...")
    
    prompt = f"""
    You are an expert Tier-3 Cybersecurity Analyst. 
    Our machine learning system just flagged a highly suspicious network log.
    
    Please review the log data below and write a brief, 1-to-2 sentence Incident Report. 
    Explain what type of attack this likely is, and recommend one immediate action in 1 sentence.
    
    RAW LOG DATA:
    - IP Address: {log_data.get('ip_address')}
    - Action Attempted: {log_data.get('action')}
    - System Message: {log_data.get('message')}
    - NLP Extracted Entities: {log_data.get('extracted_nlp_data')}
    
    INCIDENT REPORT:
    """
    
    try:
        # Call the local LLM with performance optimizations
        response = ollama.generate(
            model='llama3.2:1b', # Using the smallest, fastest model
            prompt=prompt,
            options={
                "num_thread": 8,       # Tell Ollama to use 8 CPU threads (adjust based on your AMD CPU)
                "num_predict": 100,    # Hard limit: The model cannot generate more than 100 tokens (keeps it fast)
                "temperature": 0.1     # Low temperature makes the AI less creative, which processes slightly faster
            }
        )
        return response['response'].strip()
        
    except Exception as e:
        error_msg = f"LLM Generation Failed. Make sure Ollama is running in the background. Error: {str(e)}"
        print(f"❌ {error_msg}")
        return error_msg

# --- Quick Test ---
if __name__ == "__main__":
    fake_log = {
        "ip_address": "45.33.22.11",
        "action": "SSH_LOGIN",
        "message": "Failed password for root from 45.33.22.11 port 22 ssh2",
        "extracted_nlp_data": '{"IP_ADDRESS": "45.33.22.11", "PROTOCOL": "ssh2"}'
    }
    
    print("Testing Local LLM connection...\n")
    report = generate_incident_report(fake_log)
    print("\n=== GENERATED REPORT ===")
    print(report)
    print("========================")