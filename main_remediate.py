import argparse
import time
import xml.etree.ElementTree as ET

from lib.client import SophosClient
from lib.logic import section_1, section_4, section_6
from lib.payloads import section_1 as pay1, section_4 as pay4, section_6 as pay6
from lib import backup_manager

def perform_rollback(client, name, original_xml):
    """Thực hiện rollback về trạng thái cũ"""
    print(f"   [!] Rolling back {name}...")
    if client.set_config(original_xml):
        print(f"   -> Rollback SUCCESS. System restored to previous state.")
    else:
        print(f"   -> Rollback FAILED. Manual intervention required!")

def process_item(cid, name, check_func, fix_xml, client, session_dir, entity_tag=None):
    """
    Hàm xử lý chung: Check -> Snapshot (nếu sai) -> Fix -> Verify -> Rollback
    """
    # 1. Kiểm tra tuân thủ
    is_valid, current_val = check_func(client)
    
    if is_valid:
        print(f"[SKIP] {cid} {name} compliant. (Val: {current_val})")
        return

    print(f"[FIXING] {cid} {name}... (Current: {current_val})")
    
    # 2. SNAPSHOT (Chỉ backup mục này trước khi sửa)
    original_xml = None
    if entity_tag:
        original_xml = client.get_config(entity_tag)
        if original_xml:
            filename = f"{cid}_{entity_tag}.xml"
            backup_manager.save_snapshot(session_dir, filename, original_xml)
        else:
            print("   -> [WARN] Could not fetch original config. Rollback unavailable.")

    # 3. APPLY FIX
    if client.set_config(fix_xml):
        print(f"   -> Config sent successfully.")
        
        # 4. VERIFY (Kiểm tra lại ngay lập tức)
        time.sleep(2) 
        
        is_valid_now, new_val = check_func(client)
        if is_valid_now:
            print(f"   -> Verification PASSED. New Val: {new_val}")
        else:
            print(f"   -> Verification FAILED. Value remains: {new_val}")
            # 5. ROLLBACK (Nếu fix rồi mà vẫn sai)
            if original_xml:
                perform_rollback(client, name, original_xml)
    else:
        print(f"   -> API Error during fix.")
        if original_xml:
             perform_rollback(client, name, original_xml)

def main():
    parser = argparse.ArgumentParser(description='Sophos Remediation Script')
    parser.add_argument('--ip', type=str, help='Firewall IP')
    parser.add_argument('--port', type=str, default='4444', help='Port')
    parser.add_argument('--user', type=str, help='User')
    parser.add_argument('--password', type=str, help='Pass')
    parser.add_argument('--backup-pass', type=str, default='Sophos123@**#', help='Backup Encryption Password')
    
    args = parser.parse_args()
    client = SophosClient(ip=args.ip, port=args.port, user=args.user, password=args.password)
    
    print(f"\nSTARTING AUTOMATED REMEDIATION FOR: {client.ip}")
    print("-" * 60)

    # KHỞI TẠO SESSION BACKUP
    session_dir = backup_manager.create_backup_session(client.ip)

    # SECTION 1
    process_item("1.1.1", "Admin Settings", section_1.check_1_1_1_idle_timeout, pay1.FIX_ADMIN_SETTINGS, client, session_dir, entity_tag="AdminSettings")
    process_item("1.1.2", "Disclaimer", section_1.check_1_1_2_login_disclaimer, pay1.FIX_ADMIN_SETTINGS, client, session_dir, entity_tag="AdminSettings")
    process_item("1.1.3", "NTP Settings", section_1.check_1_1_3_ntp, pay1.FIX_NTP, client, session_dir, entity_tag="Time")
    process_item("1.1.5", "Pwd Complexity", section_1.check_1_1_5_password_complexity, pay1.FIX_PASSWORD_COMPLEXITY, client, session_dir, entity_tag="AdminSettings")
    process_item("1.1.6", "Block WAN Admin", section_1.check_1_1_6_wan_access, pay1.FIX_WAN_ACCESS, client, session_dir, entity_tag="Zone")

    # SECTION 4
    process_item("4.2", "Pattern Update", section_4.check_4_2_pattern_update, pay4.FIX_PATTERN_UPDATE, client, session_dir, entity_tag="PatternDownload")
    process_item("4.3", "Auto Hotfix", section_4.check_4_3_auto_hotfix, pay4.FIX_HOTFIX, client, session_dir, entity_tag="Hotfix")
    process_item("4.4", "Auto Backup", section_4.check_4_4_backup, pay4.get_backup_payload(args.backup_pass), client, session_dir, entity_tag="BackupRestore")

    # SECTION 6
    # Các hàm này tự quản lý việc Snapshot bên trong chúng.
    
    section_6.remediate_dos_bypass_rules(client, session_dir)
    
    section_6.remediate_wifi_security(client, session_dir)

    process_item("6.7", "Spoof Prevention", section_6.check_6_7_spoof_prevention, pay6.FIX_SPOOF, client, session_dir, entity_tag="SpoofPrevention")
    process_item("6.7", "DoS Flood", section_6.check_6_7_dos_flood, pay6.FIX_DOS, client, session_dir, entity_tag="DoSSettings")
    
    print("-" * 60)

if __name__ == "__main__":
    main()