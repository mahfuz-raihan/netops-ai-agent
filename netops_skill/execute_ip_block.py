import sys
import datetime

def execute_ip_block(ip_address):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rule = f"[{timestamp}] DENY IN FROM {ip_address} # APPLIED BY OPENCLAW AGENT\n"
    try:
        # UPDATED PATH
        with open("/app/rules/firewall_rules.txt", "a") as file:
            file.write(rule)
        print(f"SUCCESS: Agent has successfully applied the firewall block for IP {ip_address}.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        execute_ip_block(sys.argv[1].strip())