from fastapi.testclient import TestClient
from main import app

# Create a test client that can talk to our FastAPI app without starting the actual server
client = TestClient(app)

def test_read_logs_endpoint():
    """Test that the dashboard can successfully fetch logs."""
    response = client.get("/logs")
    assert response.status_code == 200
    assert "logs" in response.json()
    assert isinstance(response.json()["logs"], list)

def test_normal_traffic_ingestion():
    """Test that normal, safe traffic is processed and NOT flagged as an anomaly."""
    safe_log = {
        "timestamp": "2026-04-12T10:00:00",
        "ip_address": "192.168.1.50",
        "action": "LOGIN",
        "status": "SUCCESS",
        "message": "User action completed normally"
    }
    
    response = client.post("/ingest-log", json=safe_log)
    
    # Assert the request was successful
    assert response.status_code == 200, response.text
    # Assert the ML model correctly classified it as safe
    assert response.json()["is_anomaly"] is False

def test_blocked_ips_endpoint():
    """Test that the blocked-ips endpoint returns a list."""
    response = client.get("/blocked-ips")
    assert response.status_code == 200
    assert "blocked_ips" in response.json()
    assert isinstance(response.json()["blocked_ips"], list)