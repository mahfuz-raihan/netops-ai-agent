from fastapi import FastAPI, Request
import subprocess
import requests
import os
import uvicorn
import re

app = FastAPI(title="Secure Agent Gateway")

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
MODEL = os.getenv("AGENT_MODEL", "llama3.2:1b")

@app.post("/api/agent")
async def handle_agent_task(request: Request):
    data = await request.json()
    incident_prompt = data.get("prompt", "")
    
    # NEW: Check if this is a command to execute a previously staged rule
    is_execution_order = "EXECUTE PREVIOUSLY STAGED RULE" in incident_prompt

    if is_execution_order:
        # The human has commanded the agent to execute.
        # We still ask Ollama to process the command and extract the IP to maintain the agentic workflow.
        tactical_prompt = incident_prompt + "\n\nAGENT DIRECTIVE: Extract ONLY the IP address from the execution order (e.g., 192.168.1.1)."
    else:
        # Standard anomaly investigation
        tactical_prompt = incident_prompt + "\n\nAGENT DIRECTIVE: If the log is malicious, reply with ONLY the exact IP address. If it is safe, reply 'NO_ACTION'."
    
    try:
        # 1. Talk to Ollama
        response = requests.post(f"{OLLAMA_URL}/api/generate", json={"model": MODEL, "prompt": tactical_prompt, "stream": False})
        ai_decision = response.json().get("response", "").strip()
        
        # Extract IP
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ai_decision)
        
        if ip_match:
            ip_to_block = ip_match.group(0)
            
            # 2. Execute the appropriate tool based on the context
            if is_execution_order:
                # RUN THE EXECUTION SKILL
                script_path = "/app/netops_skill/execute_ip_block.py"
                print(f"Agent executing live block on {ip_to_block}...")
            else:
                # RUN THE STAGING SKILL
                script_path = "/app/netops_skill/stage_ip_block.py"
                print(f"Agent staging block for {ip_to_block}...")

            process = subprocess.run(
                ["python", script_path, ip_to_block],
                capture_output=True, text=True
            )
            return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()}"}
            
        else:
            return {"result": f"Agent determined no action needed. Raw AI Output: {ai_decision}"}
            
    except Exception as e:
        return {"result": f"Agent Error: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)