from fastapi import FastAPI, Request
import subprocess
import requests
import os
import uvicorn
import re # <-- ADDED: For robust IP extraction

app = FastAPI(title="Secure Agent Gateway")

# Pull environment variables set by docker-compose
OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
MODEL = os.getenv("AGENT_MODEL", "llama3.2:1b")

@app.post("/api/agent")
async def handle_agent_task(request: Request):
    """Receives the alert from main.py, asks Ollama for a decision, and executes the skill."""
    data = await request.json()
    incident_prompt = data.get("prompt", "")

    # 1. Ask Ollama for a tactical decision
    # We force the LLM to output ONLY the IP address to prevent hallucinated commands
    tactical_prompt = incident_prompt + "\n\nAGENT DIRECTIVE: If the log is malicious, reply with ONLY the exact IP address (e.g., 192.168.1.1). If it is safe, reply 'NO_ACTION'."
    
    ollama_payload = {
        "model": MODEL,
        "prompt": tactical_prompt,
        "stream": False
    }
    
    try:
        # Talk to Ollama on the Windows Host
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=ollama_payload)
        ai_decision = response.json().get("response", "").strip()
        
        # 2. Execute the Skill based on the AI's decision
        # FIX: Use Regular Expressions to find the IP address, no matter what extra words the AI says
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ai_decision)
        
        if "NO_ACTION" not in ai_decision.upper() and ip_match:
            ip_to_block = ip_match.group(0)
            
            # Securely run the Python skill script
            process = subprocess.run(
                ["python", "/app/netops_skill/stage_ip_block.py", ip_to_block],
                capture_output=True, 
                text=True
            )
            return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()} | AI IP Extracted: {ip_to_block}"}
        else:
            return {"result": f"Agent determined no action needed, or failed to extract IP. Raw AI Output: {ai_decision}"}
            
    except Exception as e:
        return {"result": f"Agent Execution Error: {str(e)}"}

if __name__ == "__main__":
    # Start the Agent Gateway on port 8001
    uvicorn.run(app, host="0.0.0.0", port=8001)