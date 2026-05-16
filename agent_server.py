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
    
    is_execution_order = "EXECUTE PREVIOUSLY STAGED RULE" in incident_prompt

    if is_execution_order:
        # HUMAN APPROVED: Bypass LLM to guarantee reliable execution.
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', incident_prompt)
        
        if ip_match:
            ip_to_block = ip_match.group(0)
            print(f"Human authorized block for {ip_to_block}. Executing...")
            
            process = subprocess.run(
                ["python", "/app/netops_skill/execute_ip_block.py", ip_to_block],
                capture_output=True, text=True
            )
            return {"result": f"Execution Success: {process.stdout.strip()}"}
        else:
            return {"result": "Agent Error: Could not find IP in execution order."}

    else:
        # --- PHASE 2 UPDATE: PERSONA INJECTION ---
        tactical_prompt = incident_prompt + """
        
        AGENT DIRECTIVE: 
        If the log is safe, reply exactly with 'NO_ACTION'.
        If the log is malicious, you MUST adopt your loyal AI persona and reply EXACTLY in this format:
        "Hey boss/master! Our AI system detected hacking attempts from [INSERT IP HERE]. I have staged a firewall rule. May I block this? I am waiting for your approval."
        """
        # ------------------------------------------
        
        try:
            # Talk to Ollama
            response = requests.post(f"{OLLAMA_URL}/api/generate", json={"model": MODEL, "prompt": tactical_prompt, "stream": False})
            ai_decision = response.json().get("response", "").strip()
            
            # Use Regex to ensure the AI actually included an IP address in its chatty response
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ai_decision)
            
            if ip_match and "NO_ACTION" not in ai_decision.upper() and "I CANNOT ASSIST" not in ai_decision.upper():
                ip_to_block = ip_match.group(0)
                print(f"Agent detected threat from {ip_to_block}. Staging block...")
                
                # RUN THE STAGING SKILL
                process = subprocess.run(
                    ["python", "/app/netops_skill/stage_ip_block.py", ip_to_block],
                    capture_output=True, text=True
                )
                
                # We return the AI's chatty persona message so it appears on the Dashboard!
                return {"result": f"{ai_decision}"}
                
            else:
                return {"result": f"Agent determined no action needed or was blocked by safety filters. Raw AI Output: {ai_decision}"}
                
        except Exception as e:
            return {"result": f"Agent Error: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)