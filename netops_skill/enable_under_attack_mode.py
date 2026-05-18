import datetime


def enable_under_ddos_attack_mode():
    """
    Simulate turing on 'Cloudflare under attack mode' or a sweeping Subnet Ban.
    Blocks the entire 10.x.x.x subnet instantly to mitigate a DDoS.
    """
    timestamp = datatime.datatime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # we apply a sweeping rule that drops all the traffic from the botnet's subnet

    emergency_rule = f"f{timestamp}] Emergency Lockdown: DENY IN FROM SUBNET 10.10.0.0/8 # Mitigating DDos attack\n"

    try:
        with open("app/rules/firewall_rules.txt", "a" ) as file:
            file.write(emergency_rule)
        print("SUCCESS: Emergency Lockdown (10.10.0.0/8) has been enabled. Subnet: 10.10.0.0/8 has been blocked. DDoS mitigated.\n")
    except Exception as e:
        print(f"ERROR: Could not update firewall rules: {e}")

if __name__ == "__main__":
    enable_under_ddos_attack_mode()