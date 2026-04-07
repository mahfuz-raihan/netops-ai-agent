from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import json
from nlp_parser import extract_entities_from_log

# Initialize FastAPI app
app = FastAPI(title="NetOps-AI Log Ingestion API")

# Database setup (We changed the name slightly to create a fresh DB with a new column)
DB_NAME = "netops_logs_v2.db"

def init_db():
    """Create the SQLite database and logs table if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Notice we added an 'extracted_nlp_data' column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            action TEXT,
            status TEXT,
            message TEXT,
            extracted_nlp_data TEXT
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
        # Pass the raw message to our SpaCy NLP parser
        nlp_entities = extract_entities_from_log(log.message)
        
        # Convert the Python dictionary to a JSON string so we can save it in SQLite
        nlp_entities_json = json.dumps(nlp_entities)
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Insert the log and the new NLP data into the database
        cursor.execute('''
            INSERT INTO logs (timestamp, ip_address, action, status, message, extracted_nlp_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (log.timestamp, log.ip_address, log.action, log.status, log.message, nlp_entities_json))
        
        conn.commit()
        conn.close()
        
        # We return the extracted data in the API response so you can see it working!
        return {
            "status": "success", 
            "extracted_nlp": nlp_entities
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