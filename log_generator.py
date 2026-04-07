import requests
import random
import time
from datetime import datetime

# The URL of our FastAPI endpoint
API_URL = "http://127.0.0.1:8000/ingest-log"

# Simulated Network Data
NORMAL_IPS = ["192.168.1.15", "10.0.0.42", "172.16.0.8", "192.168.1.100"]
ATTACKER_IP = "45.33.22.11" # Simulated external attacker

ACTIONS = ["HTTP_GET", "HTTP_POST", "DB_QUERY"]
STATUSES = ["SUCCESS", "FAILED", "TIMEOUT"]

def generate_normal_log():
    """Generates standard, mostly benign network traffic."""
    ip = random.choice(NORMAL_IPS)
    action = random.choice(ACTIONS)
    status = "SUCCESS" if random.random() > 0.1 else "FAILED" # 90% success rate
    message = f"{action} request from {ip} completed with status {status}."
    
    return {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip,
        "action": action,
        "status": status,
        "message": message
    }

def generate_attack_log():
    """Generates a malicious log (e.g., SSH Brute Force)."""
    return {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ATTACKER_IP,
        "action": "SSH_LOGIN",
        "status": "FAILED",
        "message": f"Failed password for root from {ATTACKER_IP} port 22 ssh2"
    }

print("Starting Network Log Simulator...")
print("Press Ctrl+C to stop.")

try:
    while True:
        # 10% chance to simulate an attack spike, 90% chance for normal traffic
        if random.random() < 0.10:
            log_data = generate_attack_log()
            print(f"[ATTACK] Sending malicious log from {ATTACKER_IP}")
        else:
            log_data = generate_normal_log()
            print(f"[NORMAL] Sending traffic from {log_data['ip_address']}")

        # Send the JSON payload to the FastAPI server
        try:
            response = requests.post(API_URL, json=log_data)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to server: {e}. Is the FastAPI server running?")
        
        # Wait 1-3 seconds before sending the next log
        time.sleep(random.uniform(1.0, 3.0))

except KeyboardInterrupt:
    print("\nSimulator stopped by user.")