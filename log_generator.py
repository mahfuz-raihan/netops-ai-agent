import requests
import time
import random
import datetime

API_URL = "http://127.0.0.1:8000/ingest-log"
ATTACKER_IP = "45.33.22.11"

def generate_normal_log():
    ip_last_octet = random.randint(10, 200)
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip_address": f"192.168.1.{ip_last_octet}",
        "action": random.choice(["LOGIN", "GET /index.html", "LOGOUT", "POST /api/data"]),
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
    print("🚀 Starting Continuous Network Simulation...")
    
    while True: # Main loop runs forever
        print("\n--- Normal Traffic Flow ---")
        for _ in range(5):
            try:
                log = generate_normal_log()
                requests.post(API_URL, json=log)
                time.sleep(1)
            except requests.exceptions.RequestException:
                print("❌ Cannot connect to FastAPI server. Retrying in 5s...")
                time.sleep(5)
                continue
                
        print("\n🚨 Malicious Actor connected. Initiating Attack Sequence...")
        attack_count = 0
        while True:
            try:
                attack_count += 1
                log = generate_attack_log()
                response = requests.post(API_URL, json=log)
                
                # If the AI Agent successfully blocked the IP
                if response.status_code == 403:
                    print(f"🛑 FIREWALL BLOCK: Attacker IP ({ATTACKER_IP}) connection dropped!")
                    print("🛡️ Attack neutralized. Network returning to normal operations...")
                    time.sleep(3)
                    break # Break out of the attack loop, return to normal traffic loop
                
                print(f"Attack packet {attack_count} sent successfully. Waiting for AI defense...")
                time.sleep(2)
                
            except requests.exceptions.RequestException as e:
                print(f"Simulation error: {e}")
                time.sleep(5)
                break

if __name__ == "__main__":
    try:
        run_simulation()
    except KeyboardInterrupt:
        print("\n🛑 Simulation Stopped by User.")