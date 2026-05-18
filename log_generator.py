import requests
import time
import random
import datetime

API_URL = "http://127.0.0.1:8000/ingest-log"

# ── Multi-attacker pool ───────────────────────────────────────────────────────
# Add or remove IPs here to simulate coordinated multi-source attacks.
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

def run_simulation():
    print("Starting Multi-Attacker Network Simulation...")
    # print(f"   Attacker pool: {ATTACKER_IPS}\n")

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
                print("❌ Cannot connect to FastAPI server. Retrying in 5s...")
                time.sleep(5)
                continue

        # ── Attack phase — pick next attacker ─────────────────────────────────
        current_attacker = ATTACKER_IPS[attacker_index % len(ATTACKER_IPS)]
        attacker_index += 1

        print(f"\n🚨 Attacker #{attacker_index} connected: {current_attacker}")
        print("   Initiating Attack Sequence...")

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

                print(f"   Attack packet {attack_count} from {current_attacker} — awaiting AI defense...")
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


