import sys
import datetime

def stage_ip_block(ip_address):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rule = f"[PENDING APPROVAL - {timestamp}] DENY IN FROM {ip_address} # Proposed by AI Agent\n"
    try:
        # UPDATED PATH
        with open("/app/rules/staged_rules.txt", "a") as file:
            file.write(rule)
        print(f"SUCCESS: The block for IP {ip_address} has been safely staged.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        stage_ip_block(sys.argv[1].strip())