from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import json
from nlp_parser import extract_entities_from_log
from ml_anomaly_detector import detect_anomaly
from llm_reporter import generate_incident_report

# Initialize FastAPI app
app = FastAPI(title="NetOps-AI Log Ingestion API")

# Database setup (Using v4 to include the incident_report column)
DB_NAME = "netops_logs_v4.db"

def init_db():
    """Create the SQLite database and logs table with all columns if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create table with NLP, ML, and LLM columns
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
            incident_report TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Run database initialization on startup
init_db()

class LogEntry(BaseModel):
    timestamp: str
    ip_address: str
    action: str
    status: str
    message: str

@app.post("/ingest-log")
async def ingest_log(log: LogEntry):
    """Endpoint to receive logs, process them through NLP/ML/LLM, and save to SQLite."""
    try:
        # --- NLP STEP ---
        nlp_entities = extract_entities_from_log(log.message)
        nlp_entities_json = json.dumps(nlp_entities)
        
        # --- ML ANOMALY DETECTION STEP ---
        # Pass the message to our PyTorch/HuggingFace model
        ml_results = detect_anomaly(log.message)
        is_anomaly = ml_results["is_anomaly"]
        anomaly_score = ml_results["confidence_score"]
        
        # Default incident report for normal traffic
        incident_report = "N/A - Normal Traffic"
        
        # --- SPRINT 4: LLM CONTEXTUAL ANALYSIS ---
        # Trigger the LLM ONLY if the ML model flagged it as an attack
        if is_anomaly:
            print(f"\n🚨 ATTACK DETECTED! ML Confidence: {anomaly_score * 100:.2f}%")
            print(f"Target IP: {log.ip_address}")
            print("Triggering LLM for Root Cause Analysis...")
            
            # Package the data to send to the LLM
            log_dict = {
                "ip_address": log.ip_address,
                "action": log.action,
                "message": log.message,
                "extracted_nlp_data": nlp_entities_json
            }
            
            # Generate the report
            incident_report = generate_incident_report(log_dict)
            print(f"📝 LLM Incident Report Generated:\n{incident_report}\n")
        else:
            # Optional: Print normal traffic softly so you know it's working
            # print(f"✅ Normal traffic processed from {log.ip_address}")
            None

        # --- SPRINT 1: SAVE TO DATABASE ---
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Insert all data into the database
        cursor.execute('''
            INSERT INTO logs (
                timestamp, ip_address, action, status, message, 
                extracted_nlp_data, is_anomaly, anomaly_score, incident_report
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log.timestamp, log.ip_address, log.action, log.status, log.message, 
            nlp_entities_json, is_anomaly, anomaly_score, incident_report
        ))
        
        conn.commit()
        conn.close()
        
        # Return the processed data in the API response
        return {
            "status": "success", 
            "is_anomaly": is_anomaly,
            "incident_report_generated": is_anomaly
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs")
async def get_logs(limit: int = 10):
    """Helper endpoint to view the most recent logs."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return {"logs": rows}