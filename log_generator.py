import requests
import time
import random
import datetime
import json

API_URL = "http://127.0.0.1:8000/ingest-log"

# A specific IP we will use for the simulated attack
ATTACKER_IP = "45.33.22.11"

def generate_normal_log():
    ip_last_octet = random.randint(10, 200)
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip_address": f"192.168.1.{ip_last_octet}",
        "action": random.choice(["LOGIN", "GET /index.html", "LOGOUT"]),
        "status": "SUCCESS",
        "message": "User action completed normally"
    }

def generate_attack_log():
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip_address": ATTACKER_IP,
        "action": "BRUTE_FORCE_LOGIN",
        "status": "FAILED",
        "message": "Failed password for root from 45.33.22.11 port 22 ssh2 - 50 attempts in 3 seconds"
    }

def run_simulation():
    print("🚀 Starting Network Simulation...")
    print("Normal traffic flowing...")
    
    # Send some normal traffic
    for _ in range(5):
        try:
            log = generate_normal_log()
            requests.post(API_URL, json=log)
            time.sleep(1)
        except requests.exceptions.RequestException:
            print("❌ Cannot connect to FastAPI server.")
            return

    print("\n🚨 Initiating Simulated Attack Sequence from 45.33.22.11...")
    
    # Send continuous attacks until the system blocks us
    attack_count = 0
    while True:
        try:
            attack_count += 1
            log = generate_attack_log()
            response = requests.post(API_URL, json=log)
            
            # --- NEW: Handle Firewall Block ---
            if response.status_code == 403:
                print(f"🛑 BUSTED! The network firewall just blocked our IP address ({ATTACKER_IP})!")
                print("Simulation Complete: The AI Agent successfully defended the network.")
                break # End the simulation
            # -----------------------------------
            
            print(f"Attack packet {attack_count} sent successfully. Waiting for AI defense...")
            time.sleep(2)
            
        except requests.exceptions.RequestException as e:
            print(f"Simulation stopped due to connection error: {e}")
            break

if __name__ == "__main__":
    run_simulation()