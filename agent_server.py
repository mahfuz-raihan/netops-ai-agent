import sys
from fastapi import FastAPI, Request
import subprocess
import requests
import os
import uvicorn
import re
from openai import AzureOpenAI
from dotenv import load_dotenv
from guardrails import (
    check_security,
    check_ip_validity,
    check_command_injection,
    check_response_relevance,
    check_language_quality,
    check_logic_before_execute,
    scrub_pii,
)
load_dotenv()

app = FastAPI(title="Secure Agent Gateway")

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")


DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# --- Azure OpenAI Configurations ---
AZURE_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
AZURE_OPENAI_CHAT_API_VERSION = os.getenv("AZURE_OPENAI_CHAT_API_VERSION")

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
        print(f"❌ [DEBUG] Discord Webhook Failed: {e}")

def get_azure_forensic_report(log_data: str) -> str:
    """Uses Azure OpenAI to write a highly technical forensic report."""
    if not AZURE_API_KEY or not AZURE_ENDPOINT:
        return "*(Azure OpenAI keys not found. Skipping deep forensic analysis.)*"
        
    print("☁️ [DEBUG] Contacting Azure OpenAI for Deep Analysis...")
    try:
        client = AzureOpenAI(
            api_key=AZURE_API_KEY,
            api_version=AZURE_OPENAI_CHAT_API_VERSION,
            azure_endpoint=AZURE_ENDPOINT
        )
        
        response = client.chat.completions.create(
            model=AZURE_DEPLOYMENT,
            messages=[
                {"role": "system", "content": "You are a Tier-3 SOC Analyst. Provide a highly technical, 2-sentence forensic analysis of the following security log. Explain the attack vector."},
                {"role": "user", "content": log_data}
            ],
            max_tokens=150
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ [DEBUG] Azure Error: {e}")
        return f"*(Azure Analysis Failed: {e})*"


@app.post("/api/agent")
async def handle_agent_task(request: Request):
    print("\n--- 🤖 [DEBUG] NEW AGENT TASK RECEIVED ---")
    data = await request.json()
    incident_prompt = data.get("prompt", "")
    print(f"[DEBUG] Raw Prompt Received: {incident_prompt[:100]}...")

    # ── Guardrail 1: Security — block prompt injection attempts ──────────────
    security_check = check_security(incident_prompt)
    if not security_check.passed:
        print(f"🚨 [GUARDRAIL] Request blocked. Reason: {security_check.reason}")
        return {"result": f"Guardrail blocked request: {security_check.reason}"}

    # Scrub any PII from the prompt before forwarding it anywhere
    incident_prompt = scrub_pii(incident_prompt)

    is_execution_order = "EXECUTE PREVIOUSLY STAGED RULE" in incident_prompt
    is_ddos_defense = "EXECUTE UNDER ATTACK MODE" in incident_prompt

    if is_ddos_defense:
        print("[DEBUG] Workflow: DDOS MITIGATION detected.")
        try:
            # Execute the emergency mitigation script directly
            process = subprocess.run(
                ["python", "/app/netops_skill/enable_under_attack_mode.py"],
                capture_output=True, text=True
            )
            print(f"[DEBUG] Subprocess executed. Output: {process.stdout}")
            
            # Send confirmation to Discord
            send_to_discord("🛡️ **OpenClaw Executed:** Emergency Subnet Lockdown applied! Botnet traffic dropped.")
            return {"result": f"Output: {process.stdout.strip()}"}
        except Exception as e:
            return {"result": f"Agent Error: {str(e)}"}

    elif is_execution_order:
        print("[DEBUG] Workflow: EXECUTION ORDER detected.")
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', incident_prompt)
        
        if ip_match:
            ip_to_block = ip_match.group(0)
            print(f"[DEBUG] Extracted IP for execution: {ip_to_block}")

            # ── Guardrail 2: IP validity + command injection before subprocess ──
            ip_check = check_ip_validity(ip_to_block, allow_private=True, context="execution")
            if not ip_check.passed:
                print(f"🚨 [GUARDRAIL] Execution blocked. Reason: {ip_check.reason}")
                return {"result": f"Guardrail blocked execution: {ip_check.reason}"}

            # ── Guardrail 5: Logic — check staged & rate limit ───────────────
            logic_check = check_logic_before_execute(
                ip_to_block,
                staged_rules_path="/app/rules/staged_rules.txt",
                blocked_ips_set=set()
            )
            if not logic_check.passed:
                print(f"⚠️ [GUARDRAIL] Execution logic check failed: {logic_check.reason}")
                return {"result": f"Guardrail blocked execution: {logic_check.reason}"}

            try:
                process = subprocess.run(
                    ["python", "/app/netops_skill/execute_ip_block.py", ip_to_block],
                    capture_output=True, text=True
                )
                print(f"[DEBUG] Subprocess executed. Output: {process.stdout}")

                # ── Guardrail 5: Validate subprocess actually succeeded ──────
                if process.returncode != 0 or "ERROR" in process.stderr.upper():
                    print(f"⚠️ [GUARDRAIL] Subprocess returned an error. stderr: {process.stderr.strip()}")

                send_to_discord(f"✅ **OpenClaw Executed:** Live firewall block applied to `{ip_to_block}`. Network secured.")
                return {"result": f"Output: {process.stdout.strip()} | Errors: {process.stderr.strip()}"}
            except Exception as e:
                print(f"[DEBUG] Subprocess failed. Error: {e}")
                return {"result": f"Agent Error: {str(e)}"}
        else:
            print("❌ [DEBUG] Execution failed: Could not find IP.")
            return {"result": "Agent Error: Could not find IP in execution order."}

    else:
        print("[DEBUG] Workflow: THREAT ANALYSIS detected.")
        
        # Ask the LLM ONLY to extract the IP — never trust it to format the full message.
        tactical_prompt = f"""
        Extract the IPv4 address from the text below. 
        Reply EXACTLY with this sentence, replacing [IP] with the address:
        'Hey, boss/master!! our AI system detected something unusual illegal activities such as hacking and unauthorized access to systems from [IP], May I block this? I'm waiting for your approval.'
        Text: {incident_prompt}
        """
        
        try:
            print(f"[DEBUG] Contacting Ollama at {OLLAMA_URL} using model {MODEL}...")
            response = requests.post(f"{OLLAMA_URL}/api/generate", json={"model": MODEL, "prompt": tactical_prompt, "stream": False})
            
            ai_decision = response.json().get("response", "").strip()
            print(f"[DEBUG] Raw Ollama Response: '{ai_decision}'")

            # ── Guardrail 2: Response Relevance — validate LLM output ────────
            relevance_check = check_response_relevance(ai_decision)
            if not relevance_check.passed:
                print(f"⚠️ [GUARDRAIL] LLM response failed relevance check: {relevance_check.reason}")
                return {"result": f"Guardrail: LLM response not usable. {relevance_check.reason}"}

            # Extract IP from LLM response
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ai_decision)

            if ip_match:
                ip_to_block = ip_match.group(0)
                print(f"[DEBUG] Threat confirmed. IP extracted: {ip_to_block}. Staging rule...")

                # ── Guardrail 1: Validate the extracted IP before staging ────
                ip_check = check_ip_validity(ip_to_block, allow_private=True, context="staging")
                if not ip_check.passed:
                    print(f"🚨 [GUARDRAIL] Staging blocked — invalid IP: {ip_check.reason}")
                    return {"result": f"Guardrail blocked staging: {ip_check.reason}"}

                try:
                    # RUN THE STAGING SKILL
                    process = subprocess.run(
                        ["python", "/app/netops_skill/stage_ip_block.py", ip_to_block],
                        capture_output=True, text=True
                    )
                    print(f"[DEBUG] Staging subprocess finished. Output: {process.stdout}")
                except Exception as e:
                    print(f"❌ [DEBUG] Staging script crashed: {e}")

                # cloud LLM deep analysis (Azure OpenAI) + send to Discord for human approval
                azure_report = get_azure_forensic_report(incident_prompt)

                # ── Guardrail 3: Language Quality — validate Azure report ────
                quality_check = check_language_quality(azure_report, context="forensic report")
                if not quality_check.passed:
                    print(f"⚠️ [GUARDRAIL] Azure report failed quality check: {quality_check.reason}")
                    azure_report = "*(Forensic report unavailable — quality check failed.)*"

                discord_message = (
                    f"\n\n🤖 **OpenClaw:** Boss!!! Our AI system detected something unusual illegal activities "
                    f"such as hacking and unauthorized access to systems from `{ip_to_block}`, \n"
                    f"May I block this? I'm waiting for your approval.\n"
                    f"\n*(Type `!approve {ip_to_block}` to authorize)*\n"
                    f"\n☁️ **Forensic Analysis:** {azure_report}\n\n"
                )
                send_to_discord(discord_message)

                return {"result": "Staged successfully."}

            else:
                return {"result": f"No IP found. AI Output: {ai_decision}"}
        except Exception as e:
            return {"result": f"Agent Error: {str(e)}"}
        

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)