from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import json
from nlp_parser import extract_entities_from_log
from ml_anomaly_detector import detect_anomaly

# Initialize FastAPI app
app = FastAPI(title="NetOps-AI Log Ingestion API")

# Database setup (Changed to v3 to trigger a fresh database creation)
DB_NAME = "netops_logs_v3.db"

def init_db():
    """Create the SQLite database and logs table if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Notice we added is_anomaly and anomaly_score
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
            anomaly_score REAL
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

@app.post("/ingest-log")
async def ingest_log(log: LogEntry):
    """Endpoint to receive network logs, parse them via NLP, and save to SQLite."""
    try:
        # --- NLP STEP ---
        nlp_entities = extract_entities_from_log(log.message)
        nlp_entities_json = json.dumps(nlp_entities)
        
        # --- ML ANOMALY DETECTION STEP ---
        # Pass the message to our PyTorch/HuggingFace model
        ml_results = detect_anomaly(log.message)
        is_anomaly = ml_results["is_anomaly"]
        anomaly_score = ml_results["confidence_score"]
        
        # (Optional) Log to terminal if an attack is detected
        if is_anomaly:
            print(f"🚨 ALERT! Anomaly detected with {anomaly_score*100}% confidence: {log.ip_address}")
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Insert all data into the database
        cursor.execute('''
            INSERT INTO logs (timestamp, ip_address, action, status, message, extracted_nlp_data, is_anomaly, anomaly_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (log.timestamp, log.ip_address, log.action, log.status, log.message, nlp_entities_json, is_anomaly, anomaly_score))
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success", 
            "extracted_nlp": nlp_entities,
            "ml_analysis": ml_results
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs")
async def get_logs(limit: int = 10):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return {"logs": rows}