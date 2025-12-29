import argparse
from lib.client import SophosClient
from lib.logic import section_1, section_4, section_6

def print_row(cid, status, val):
    s_txt = "PASS" if status else "FAIL"
    print(f"{cid:<15} | {s_txt:<6} | {val}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, help='Firewall IP')
    parser.add_argument('--port', type=str, default='4444', help='Port')
    parser.add_argument('--user', type=str, help='User')
    parser.add_argument('--password', type=str, help='Pass')
    args = parser.parse_args()

    # Truyền tham số vào Client
    client = SophosClient(ip=args.ip, port=args.port, user=args.user, password=args.password)
    print(f"\nSOPHOS CIS AUDIT REPORT: {client.ip}")
    print("-" * 60)
    print(f"{'CIS ID':<15} | {'STATE':<6} | {'VALUE / DETAILS'}")
    print("-" * 60)

    # --- SECTION 1 ---
    r, v = section_1.check_1_1_1_idle_timeout(client)
    print_row("1.1.1 Timeout", r, v)
    
    r, v = section_1.check_1_1_2_login_disclaimer(client)
    print_row("1.1.2 Disclaimer", r, v)

    r, v = section_1.check_1_1_3_ntp(client)
    print_row("1.1.3 NTP", r, v)

    r, v = section_1.check_1_1_5_password_complexity(client)
    print_row("1.1.5 PwdComp", r, v)

    r, v = section_1.check_1_1_6_wan_access(client)
    print_row("1.1.6 WAN Admin", r, v)

    # --- SECTION 4 ---
    print("-" * 60)
    r, v = section_4.check_4_2_pattern_update(client)
    print_row("4.2 Patterns", r, v)

    r, v = section_4.check_4_3_auto_hotfix(client)
    print_row("4.3 Hotfix", r, v)
    
    r, v = section_4.check_4_4_backup(client)
    print_row("4.4 Backup", r, v)

    # --- SECTION 6 ---
    print("-" * 60)
    r, v = section_6.check_6_7_spoof_prevention(client)
    print_row("6.7 Spoofing", r, v)

    r, v = section_6.check_6_7_dos_flood(client)
    print_row("6.7 DoS Flood", r, v)
    
    r, v = section_6.check_6_9_wireless_all(client)
    print_row("6.9 Wifi All", r, v)
    
    r, v = section_6.check_6_8_risky_services_wan(client)
    print_row("6.8 Risky Svcs", r, v)

    r, v = section_6.check_6_10_any_any_wan(client)
    print_row("6.10 Any-Any", r, v)
    
    print("-" * 60)

if __name__ == "__main__":
    main()