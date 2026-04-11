from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import json
import requests
import os
import datetime
from fastapi.middleware.cors import CORSMiddleware

# Import custom AI modules 
from nlp_parser import extract_entities_from_log
from ml_anomaly_detector import detect_anomaly

app = FastAPI(title="NetOps-AI Log Ingestion API")

# CORS Middleware for Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_NAME = "netops_logs_v5.db"
BLOCKED_IPS = set()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            action TEXT,
            status TEXT,
            message TEXT,
            extracted_nlp_data TEXT,
            is_anomaly BOOLEAN,
            anomaly_score REAL,
            agent_report TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class LogEntry(BaseModel):
    timestamp: str
    ip_address: str
    action: str
    status: str
    message: str

def is_ip_blocked(ip_address: str) -> bool:
    if ip_address in BLOCKED_IPS:
        return True
    if not os.path.exists("rules/firewall_rules.txt"):
        return False
    try:
        with open("rules/firewall_rules.txt", "r") as file:
            rules = file.read()
            if ip_address in rules:
                BLOCKED_IPS.add(ip_address) 
                return True
    except Exception:
        pass
    return False

@app.post("/ingest-log")
async def ingest_log(log: LogEntry):
    # Enforce Firewall
    if is_ip_blocked(log.ip_address):
        print(f"🛑 FIREWALL BLOCK: Dropped connection from blocked IP {log.ip_address}")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO logs (timestamp, ip_address, action, status, message, extracted_nlp_data, is_anomaly, anomaly_score, agent_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (log.timestamp, log.ip_address, "FIREWALL_DROP", "BLOCKED", "Connection instantly dropped by AI Firewall Rule", "{}", False, 0.0, "Auto-blocked by OpenClaw Agent."))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=403, detail="Connection Dropped by Firewall")

    try:
        nlp_entities = extract_entities_from_log(log.message)
        nlp_entities_json = json.dumps(nlp_entities)
        
        ml_results = detect_anomaly(log.message)
        is_anomaly = ml_results["is_anomaly"]
        anomaly_score = ml_results["confidence_score"]
        agent_report = "N/A - Normal Traffic"
        
        if is_anomaly:
            print(f"\n🚨 ATTACK DETECTED! ML Confidence: {anomaly_score * 100:.2f}%")
            print("Triggering Secure OpenClaw Agent in Docker...")
            
            agent_prompt = f"""
            SYSTEM INSTRUCTIONS:
            You are a restricted security agent. Evaluate the UNTRUSTED LOG DATA below and use the `stage_ip_block` tool if the IP is malicious.
            --- BEGIN UNTRUSTED LOG DATA ---
            Target IP: {log.ip_address}
            Action Attempted: {log.action}
            Message: {log.message}
            --- END UNTRUSTED LOG DATA ---
            """
            
            try:
                agent_response = requests.post(
                    "http://127.0.0.1:8001/api/agent", 
                    json={"prompt": agent_prompt},
                    timeout=30
                )
                if agent_response.status_code == 200:
                    agent_report = agent_response.json().get("result", "Agent executed successfully.")
                    print(f"🤖 Agent Action Log:\n{agent_report}\n")
                else:
                    agent_report = f"Agent API Error: {agent_response.status_code} - {agent_response.text}"
                    print(f"❌ {agent_report}")
            except requests.exceptions.RequestException as e:
                agent_report = f"Failed to reach Docker Agent at port 8001. Error: {str(e)}"
                print(f"❌ {agent_report}")
        else:
            print(f"✅ Normal traffic processed from {log.ip_address}")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO logs (timestamp, ip_address, action, status, message, extracted_nlp_data, is_anomaly, anomaly_score, agent_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (log.timestamp, log.ip_address, log.action, log.status, log.message, nlp_entities_json, is_anomaly, anomaly_score, agent_report))
        conn.commit()
        conn.close()
        
        return {"status": "success", "is_anomaly": is_anomaly}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs")
async def get_logs(limit: int = 50):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = [dict(row) for row in cursor.fetchall()] 
    conn.close()
    return {"logs": rows}

class ApproveAction(BaseModel):
    ip_address: str

@app.post("/approve-block")
async def approve_block(action: ApproveAction):
    print(f"\n🛡️ HUMAN OVERRIDE: Admin approved block for IP {action.ip_address}")
    print("Delegating execution command back to OpenClaw Agent...")
    
    execution_prompt = f"""
    SYSTEM COMMAND: EXECUTE PREVIOUSLY STAGED RULE
    Human authorization received. 
    You are cleared to use the `execute_ip_block` tool on IP: {action.ip_address}
    """
    
    try:
        agent_response = requests.post(
            "http://127.0.0.1:8001/api/agent", 
            json={"prompt": execution_prompt},
            timeout=10
        )
        if agent_response.status_code == 200:
            result = agent_response.json().get("result", "")
            print(f"🤖 Agent Execution Log:\n{result}")
            BLOCKED_IPS.add(action.ip_address)
            return {"status": "success", "message": f"Agent successfully executed block on {action.ip_address}."}
        else:
            raise HTTPException(status_code=500, detail="Agent rejected execution command.")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to reach Agent: {str(e)}")

@app.get("/blocked-ips")
async def get_blocked_ips():
    blocked_list = list(BLOCKED_IPS)
    if os.path.exists("rules/firewall_rules.txt"):
        try:
            with open("rules/firewall_rules.txt", "r") as file:
                rules = file.read()
                for line in rules.split('\n'):
                    if "DENY IN FROM" in line:
                        parts = line.split("DENY IN FROM ")
                        if len(parts) > 1:
                            ip = parts[1].split()[0]
                            if ip not in blocked_list:
                                blocked_list.append(ip)
        except Exception:
            pass
    return {"blocked_ips": blocked_list}