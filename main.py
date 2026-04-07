from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import datetime
from typing import Optional

# Initialize FastAPI app
app = FastAPI(title="NetOps-AI Log Ingestion API")

# Database setup
DB_NAME = "netops_logs.db"

def init_db():
    """Create the SQLite database and logs table if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            action TEXT,
            status TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Run DB initialization on startup
init_db()

# Pydantic model to validate incoming JSON data
class LogEntry(BaseModel):
    timestamp: str
    ip_address: str
    action: str
    status: str
    message: str

@app.post("/ingest-log")
async def ingest_log(log: LogEntry):
    """Endpoint to receive network logs and save them to SQLite."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Insert the log into the database
        cursor.execute('''
            INSERT INTO logs (timestamp, ip_address, action, status, message)
            VALUES (?, ?, ?, ?, ?)
        ''', (log.timestamp, log.ip_address, log.action, log.status, log.message))
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": "Log ingested successfully"}
    
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