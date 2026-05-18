import requests
import time
import random
import datetime

API_URL = "http://127.0.0.1:8000/ingest-log"

# ── Multi-attacker pool ───────────────────────────────────────────────────────
ATTACKER_IPS = [
    "45.33.22.11",    # Original attacker
    "185.220.101.45", # Tor exit node
    "62.102.148.68",  # Known scanner
    "198.199.122.89", # VPS attacker
    "103.21.244.10",  # APT source
]

ATTACK_TYPES = [
    ("SSH_LOGIN",   "FAILED", "Failed password for root from {ip} port 22 ssh2 - 50 attempts in 3 seconds"),
    ("HTTP",        "FAILED", "SQL injection attempt detected from {ip}: GET /admin?id=1 OR 1=1--"),
    ("PORT_SCAN",   "FAILED", "Nmap port scan detected from {ip} — 500 ports probed in 2 seconds"),
    ("BRUTE_FORCE_LOGIN", "FAILED", "Credential stuffing attack from {ip} — 200 login attempts in 60 seconds"),
    ("RDP",         "FAILED", "RDP brute-force from {ip} port 3389 — repeated failed authentications"),
]

def generate_normal_log():
    ip_last_octet = random.randint(10, 200)
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip_address": f"192.168.1.{ip_last_octet}",
        "action": random.choice(["LOGIN", "LOGOUT", "HTTP"]),
        "status": "SUCCESS",
        "message": "User action completed normally"
    }

def generate_attack_log(attacker_ip: str):
    action, status, msg_template = random.choice(ATTACK_TYPES)
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip_address": attacker_ip,
        "action": action,
        "status": status,
        "message": msg_template.format(ip=attacker_ip),
    }

def generate_ddos_log():
    """Generate a high-volume log line simulating a UDP flood from a random 10.x.x.x IP."""
    ip_address = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip_address": ip_address, 
        "action": "HTTP_GET /",
        "status": "FAILED",
        "message": f"UDP flood - massive traffic spike detected"
    }

def run_simulation():
    print("🚀 Starting Multi-Attacker Network Simulation...")

    attacker_index = 0  # Round-robin through the attacker pool

    while True:
        # ── Normal traffic phase ──────────────────────────────────────────────
        print("\n--- Normal Traffic Flow ---")
        for _ in range(5):
            try:
                log = generate_normal_log()
                requests.post(API_URL, json=log, timeout=5)
                time.sleep(1)
            except requests.exceptions.RequestException:
                print("❌ Cannot connect to server. Retrying in 5s...")
                time.sleep(5)
                continue

        # ── Determine Attack Type (Targeted vs DDoS) ──────────────────────────
        # 20% chance for a massive DDoS flood, 80% chance for a targeted attack
        is_ddos = random.random() < 0.20

        if is_ddos:
            print("\n🚨🚨🚨 MASSIVE DDOS BOTNET DETECTED! 🚨🚨🚨")
            print("Flooding server with UDP requests from random 10.x.x.x subnets...")
            
            attack_count = 0
            while True:
                try:
                    # Fire 5 logs instantly with no delay to simulate a flood
                    for _ in range(5):
                        attack_count += 1
                        log = generate_ddos_log()
                        response = requests.post(API_URL, json=log, timeout=5)
                        
                        # If the server drops the connection, it means the subnet ban worked!
                        if response.status_code == 403:
                            print(f"\n🛑 FIREWALL BLOCK: Botnet traffic dropped after {attack_count} packets!")
                            print("🛡️ DDoS Mitigated! Returning to normal operations...\n")
                            break
                            
                    if response.status_code == 403:
                        time.sleep(3)
                        break 
                        
                    print(f"  Flood batch {attack_count} sent... server still standing.")
                    time.sleep(0.5) # Slight pause so we don't accidentally crash our own local PC!
                    
                except requests.exceptions.RequestException as e:
                    print(f"Simulation error: {e}")
                    time.sleep(5)
                    break
                    
        else:
            # ── Targeted Attack phase ─────────────────────────────────────────
            current_attacker = ATTACKER_IPS[attacker_index % len(ATTACKER_IPS)]
            attacker_index += 1

            print(f"\n🚨 Attacker #{attacker_index} connected: {current_attacker}")
            print("  Initiating Targeted Attack Sequence...")

            attack_count = 0
            while True:
                try:
                    attack_count += 1
                    log = generate_attack_log(current_attacker)
                    response = requests.post(API_URL, json=log, timeout=5)

                    if response.status_code == 403:
                        print(f"🛑 FIREWALL BLOCK: {current_attacker} connection dropped after {attack_count} packets!")
                        print("🛡️  Attack neutralized. Returning to normal operations...\n")
                        time.sleep(3)
                        break

                    print(f" Attack packet {attack_count} from {current_attacker} — awaiting AI defense...")
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