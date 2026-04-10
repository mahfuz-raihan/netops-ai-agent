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
    
    # Check if this is a command to execute a previously staged rule
    is_execution_order = "EXECUTE PREVIOUSLY STAGED RULE" in incident_prompt

    if is_execution_order:
        # HUMAN APPROVED: Bypass the LLM to guarantee reliable execution.
        # Use Regex to extract the IP directly from the human's prompt.
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', incident_prompt)
        
        if ip_match:
            ip_to_block = ip_match.group(0)
            print(f"Human authorized block for {ip_to_block}. Executing...")
            
            # RUN THE EXECUTION SKILL
            process = subprocess.run(
                ["python", "/app/netops_skill/execute_ip_block.py", ip_to_block],
                capture_output=True, text=True
            )
            return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()}"}
        else:
            return {"result": "Agent Error: Could not find IP in execution order."}

    else:
        # UNKNOWN THREAT: Use the LLM to analyze the log and extract the attacker IP
        tactical_prompt = incident_prompt + "\n\nAGENT DIRECTIVE: If the log is malicious, reply with ONLY the exact IP address. If it is safe, reply 'NO_ACTION'."
        
        try:
            # Talk to Ollama
            response = requests.post(f"{OLLAMA_URL}/api/generate", json={"model": MODEL, "prompt": tactical_prompt, "stream": False})
            ai_decision = response.json().get("response", "").strip()
            
            # Extract IP from LLM response
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ai_decision)
            
            if ip_match and "NO_ACTION" not in ai_decision.upper():
                ip_to_block = ip_match.group(0)
                print(f"Agent detected threat. Staging block for {ip_to_block}...")
                
                # RUN THE STAGING SKILL
                process = subprocess.run(
                    ["python", "/app/netops_skill/stage_ip_block.py", ip_to_block],
                    capture_output=True, text=True
                )
                return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()}"}
                
            else:
                return {"result": f"Agent determined no action needed. Raw AI Output: {ai_decision}"}
                
        except Exception as e:
            return {"result": f"Agent Error: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)