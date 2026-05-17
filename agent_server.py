from fastapi import FastAPI, Request
import subprocess
import requests
import os
import uvicorn
import re

app = FastAPI(title="Secure Agent Gateway")

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")


DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

def send_to_discord(message: str):
    """Helper function to send messages to Discord with explicit error logging."""
    if not DISCORD_WEBHOOK_URL or not DISCORD_WEBHOOK_URL.startswith("http"):
        print("❌ DISCORD ERROR: Webhook URL is missing or invalid in agent_server.py!")
        return
        
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message}, timeout=10)
        if response.status_code in [200, 204]:
            print("✅ [DEBUG] Discord Webhook delivered successfully!")
        else:
            print(f"❌ [DEBUG] Discord rejected the Webhook. Code: {response.status_code}, Reason: {response.text}")
    except Exception as e:
        print(f"❌ [DEBUG] Failed to reach Discord servers entirely: {e}")

@app.post("/api/agent")
async def handle_agent_task(request: Request):
    print("\n--- 🤖 [DEBUG] NEW AGENT TASK RECEIVED ---")
    data = await request.json()
    incident_prompt = data.get("prompt", "")
    print(f"[DEBUG] Raw Prompt Received: {incident_prompt[:100]}...")
    
    is_execution_order = "EXECUTE PREVIOUSLY STAGED RULE" in incident_prompt

    if is_execution_order:
        print("[DEBUG] Workflow: EXECUTION ORDER detected.")
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', incident_prompt)
        
        if ip_match:
            ip_to_block = ip_match.group(0)
            print(f"[DEBUG] Extracted IP for execution: {ip_to_block}")
            try:
                process = subprocess.run(
                    ["python", "/app/netops_skill/execute_ip_block.py", ip_to_block],
                    capture_output=True, text=True
                )
                print(f"[DEBUG] Subprocess executed. Output: {process.stdout}")
                
                # Tell Discord that the execution was successful
                send_to_discord(f"✅ **OpenClaw Executed:** Live firewall block applied to `{ip_to_block}`. Network secured.")
                
                return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()}"}
            except Exception as e:
                 print(f"❌ [DEBUG] Subprocess crash: {e}")
                 return {"result": f"Agent Error: {str(e)}"}
        else:
             print("❌ [DEBUG] Execution failed: Could not find IP.")
             return {"result": "Agent Error: Could not find IP in execution order."}

    else:
        print("[DEBUG] Workflow: THREAT ANALYSIS detected.")
        
        # Ask the LLM ONLY to extract the IP — never trust it to format the full message.
        tactical_prompt = f"""
        Your only job is to extract the IPv4 address from the text below.
        Reply with ONLY the IPv4 address, nothing else. No sentences, no extra words.

        Text: {incident_prompt}
        """
        
        try:
            print(f"[DEBUG] Contacting Ollama at {OLLAMA_URL} using model {MODEL}...")
            response = requests.post(f"{OLLAMA_URL}/api/generate", json={"model": MODEL, "prompt": tactical_prompt, "stream": False})
            
            ai_decision = response.json().get("response", "").strip()
            print(f"[DEBUG] Raw Ollama Response: '{ai_decision}'")
            
            # Extract IP from LLM response
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ai_decision)
            
            if ip_match:
                ip_to_block = ip_match.group(0)
                print(f"[DEBUG] Threat confirmed. IP extracted: {ip_to_block}. Staging rule...")
                
                try:
                    # RUN THE STAGING SKILL
                    process = subprocess.run(
                        ["python", "/app/netops_skill/stage_ip_block.py", ip_to_block],
                        capture_output=True, text=True
                    )
                    print(f"[DEBUG] Staging subprocess finished. Output: {process.stdout}")
                except Exception as e:
                    print(f"❌ [DEBUG] Staging script crashed: {e}")
                
                # Build the Discord message from a fixed Python template — never trust the LLM to format it.
                discord_message = (
                    f"**OpenClaw:** Boss!!! Our AI system detected something unusual illegal activities "
                    f"such as hacking and unauthorized access to systems from `{ip_to_block}`, "
                    f"May I block this? I'm waiting for your approval."
                    f"\n\n*(Type `!approve {ip_to_block}` to authorize)*"
                )
                send_to_discord(discord_message)
                
                return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()}"}
                
            else:
                print("[DEBUG] No IP found in LLM response.")
                return {"result": f"Agent determined no action needed. Raw AI Output: {ai_decision}"}
                
        except Exception as e:
            print(f"❌ [DEBUG] Major Exception in THREAT ANALYSIS: {str(e)}")
            return {"result": f"Agent Error: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)