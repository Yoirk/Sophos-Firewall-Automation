import xml.etree.ElementTree as ET
from lib.payloads import section_6 as pay6
from lib import backup_manager

def check_6_7_spoof_prevention(client):
    xml = client.get_config("SpoofPrevention")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    # Check lỗi API
    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"

    # --- 1. Kiểm tra nút bật tổng (Master Switch) ---
    master_node = root.find(".//SpoofPrevention/SpoofPrevention")
    # Nếu không tìm thấy thẻ hoặc giá trị không phải Enable -> FAIL luôn
    if master_node is None or master_node.text != "Enable":
        return False, "Spoof Prevention is Disabled"

    # --- 2. Kiểm tra Zone (Chỉ chạy khi Master đã Bật) ---
    # Lấy danh sách các Zone đang được cấu hình
    zones = [z.text for z in root.findall(".//IPSpoofing/EnableOnZone/Zone") if z.text]
    
    missing_zones = []
    # Chuẩn CIS yêu cầu phải có LAN và DMZ
    if "LAN" not in zones: missing_zones.append("LAN")
    if "DMZ" not in zones: missing_zones.append("DMZ")

    if missing_zones:
        return False, f"Enabled but missing coverage for: {', '.join(missing_zones)}"

    return True, f"Enabled on {', '.join(zones)}"

def check_6_7_dos_flood(client):
    xml = client.get_config("DoSSettings")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"

    # Danh sách các mục cần kiểm tra (theo cấu trúc Entities.xml)
    # Format: (Tên hiển thị, Đường dẫn XPath tới ApplyFlag)
    checks = [
        ("SYN Flood Src", ".//SYNFlood/Source/ApplyFlag"),
        ("SYN Flood Dst", ".//SYNFlood/Destination/ApplyFlag"),
        ("UDP Flood Src", ".//UDPFlood/Source/ApplyFlag"),
        ("UDP Flood Dst", ".//UDPFlood/Destination/ApplyFlag"),
        ("TCP Flood Src", ".//TCPFlood/Source/ApplyFlag"),
        ("TCP Flood Dst", ".//TCPFlood/Destination/ApplyFlag"),
        ("ICMP Flood Src", ".//ICMPFlood/Source/ApplyFlag"),
        ("ICMP Flood Dst", ".//ICMPFlood/Destination/ApplyFlag"),
        ("Src Routed", ".//DroppedSourceRoutedPackets/Destination/ApplyFlag"),
        ("ICMP Redirect", ".//DisableICMPRedirectPacket/Destination/ApplyFlag"),
        ("ARP Hardening", ".//DisableARPFlooding/Destination/ApplyFlag")
    ]

    failed_items = []
    for name, xpath in checks:
        node = root.find(xpath)
        val = node.text if node is not None else "Disable"
        if val != "Enable":
            failed_items.append(name)

    if not failed_items:
        return True, "All DoS Protections Enabled"
    else:
        return False, f"Disabled: {', '.join(failed_items)}"

def check_dos_bypass_rules(client):
    """
    Kiểm tra xem các mạng tin cậy (LAN & Tailscale) đã được thêm vào Bypass chưa.
    """
    # Gọi API lấy danh sách Rule hiện tại
    xml = client.get_config("DoSBypassRules")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    # Danh sách các mạng bắt buộc phải có (giống bên payload)
    required_subnets = ["172.16.16.0/24", "100.64.0.0/10"]
    
    # Lấy tất cả SourceIPNetmask đang có trên Firewall
    # XPath tìm tất cả thẻ SourceIPNetmask bất kể cấu trúc XML trả về thế nào
    existing_sources = [node.text for node in root.findall(".//SourceIPNetmask") if node.text]
    
    # Tìm những mạng còn thiếu
    missing_subnets = [net for net in required_subnets if net not in existing_sources]

    if not missing_subnets:
        return True, "All trusted networks bypassed"
    else:
        # Trả về False và danh sách các mạng còn thiếu để main biết đường fix
        return False, missing_subnets
    
def check_6_9_wireless_all(client):
    xml = client.get_config("WirelessNetworks")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"
    
    networks = root.findall(".//WirelessNetworks")
    if not networks: return True, "No Wireless Networks"

    insecure_list = []
    for net in networks:
        # Lấy Status an toàn
        status_node = net.find("Status")
        status = status_node.text if status_node is not None else "Disable"
        if status != "Enable": continue

        name_node = net.find("Name")
        name = name_node.text if name_node is not None else "Unknown"

        # Nếu không có thẻ Encryption (do NoEncryption), gán mặc định là "None"
        enc_node = net.find("Encryption")
        enc = enc_node.text if enc_node is not None else "None"

        mode_node = net.find("SecurityMode")
        mode = mode_node.text if mode_node is not None else "None"

        iso_node = net.find("ClientIsolation")
        iso = iso_node.text if iso_node is not None else "Disable"
        # -----------------------------

        # Điều kiện chuẩn CIS: WPA2 + AES + Isolation Enabled
        is_secure = ("AES" in enc) and ("WPA2" in mode) and (iso == "Enabled")
        
        if not is_secure:
            insecure_list.append(f"{name}({mode}/{enc}/Iso:{iso})")
    
    if insecure_list:
        return False, f"Insecure: {', '.join(insecure_list)}"
    
    return True, "All Active Wifi Secure"

def check_6_8_risky_services_wan(client):
    xml = client.get_config("FirewallRule")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"

    # Danh sách từ khóa rủi ro mở rộng theo chuẩn CIS
    risky_keywords = [
        "SMB", "Netbios", "RDP", "Remote Desktop", 
        "FTP", "Telnet", "SSH", "VNC", "SQL", "LDAP"
    ]

    violations = []
    for rule in root.findall(".//FirewallRule"):
        # Chỉ xét rule đang BẬT và hành động là ACCEPT
        status = rule.find("Status").text
        action = rule.find("PolicyType").text if rule.find("PolicyType") is not None else "Network" # Mặc định check Network rules
        
        if status != "Enable": continue

        # Kiểm tra nguồn là WAN hoặc Any
        src_zones = [z.text for z in rule.findall(".//SourceZones/Zone") if z.text]
        if "WAN" not in src_zones and "Any" not in src_zones:
            continue

        # Kiểm tra dịch vụ
        services = [s.text for s in rule.findall(".//Services/Service") if s.text]
        rule_name = rule.find("Name").text

        # Nếu dịch vụ là Any -> Vi phạm (Bao gom cả 6.8)
        if "Any" in services:
             violations.append(f"Rule '{rule_name}' allows ANY service")
             continue

        # Nếu dịch vụ chứa từ khóa rủi ro
        for s in services:
            if any(k.lower() in s.lower() for k in risky_keywords):
                violations.append(f"Rule '{rule_name}' exposes {s}")

    if violations:
        return False, f"{'; '.join(violations)}"
    
    return True, "No risky services exposed from WAN"

def check_6_10_any_any_wan(client):
    xml = client.get_config("FirewallRule")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)
    
    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"

    violations = []
    for rule in root.findall(".//FirewallRule"):
        if rule.find("Status").text != "Enable": continue

        # Điều kiện 1: Source Zone là WAN hoặc Any
        src_zones = [z.text for z in rule.findall(".//SourceZones/Zone") if z.text]
        if "WAN" not in src_zones and "Any" not in src_zones:
            continue

        # Điều kiện 2: Destination Network là Any
        dst_nets = [n.text for n in rule.findall(".//DestinationNetworks/Network") if n.text]
        
        # Điều kiện 3: Service là Any
        services = [s.text for s in rule.findall(".//Services/Service") if s.text]

        if "Any" in dst_nets and "Any" in services:
            name = rule.find("Name").text
            violations.append(f"Rule '{name}' is ANY-ANY from WAN")

    if violations:
        return False, f"{'; '.join(violations)}"

    return True, "No ANY-ANY rules from WAN"

def remediate_dos_bypass_rules(client, session_dir):
    """Xử lý tuân thủ và sửa lỗi cho DoS Bypass Rules."""
    print("[CHECKING] DoS Bypass Rules...")
    is_compliant, result = check_dos_bypass_rules(client)

    if is_compliant:
        print(f"[SKIP] DoS Bypass Rules are already compliant. ({result})")
        return

    missing_list = result 
    print(f"[FIXING] Found missing bypass rules for: {missing_list}. Applying fixes...")
    
    # 1. Snapshot DoS Bypass Rules
    bypass_xml = client.get_config("DoSBypassRule")
    if bypass_xml:
        backup_manager.save_snapshot(session_dir, "6.7_DoSBypassRule.xml", bypass_xml)

    # 2. Apply fix sử dụng payloads
    all_payloads = pay6.get_safe_bypass_payloads()
    for rule_xml in all_payloads:
        # Chỉ apply payload nào chứa subnet bị thiếu
        if any(subnet in rule_xml for subnet in missing_list):
            if client.set_config(rule_xml):
                print(f"   -> Rule added successfully.")
            else:
                print(f"   -> Failed to add rule.")

def remediate_wifi_security(client, session_dir):
    "Xử lý tuân thủ cho toàn bộ Wifi Networks"
    print("[CHECKING] 6.9 Wireless Networks for Bulk Fix...")
    
    # 1. Lấy Config
    xml = client.get_config("WirelessNetworks")
    if not xml: return
    root = ET.fromstring(xml)
    
    if root.tag == "Response" and root.find("Status") is not None:
         print(f"[ERROR] API Error in 6.9: {root.find('Status').text}")
         return

    # 2. Tìm mạng lỗi
    networks_to_fix = []
    for net in root.findall(".//WirelessNetworks"):
        status_node = net.find("Status")
        status = status_node.text if status_node is not None else "Disable"
        if status != "Enable": continue

        enc_node = net.find("Encryption")
        enc = enc_node.text if enc_node is not None else "None"
        iso_node = net.find("ClientIsolation")
        iso = iso_node.text if iso_node is not None else "Disable"

        # Check lỗi: Không phải AES hoặc Isolation tắt
        if "AES" not in enc or iso != "Enabled":
            networks_to_fix.append(net)

    if not networks_to_fix:
        print(f"[SKIP] 6.9 All active Wireless Networks are secure.")
        return

    # 3. Snapshot
    print(f"[FIXING] Found {len(networks_to_fix)} insecure networks. Taking snapshot...")
    backup_manager.save_snapshot(session_dir, "6.9_WirelessNetworks_Full.xml", xml)

    # 4. Sửa trực tiếp trên node XML
    for net in networks_to_fix:
        name = net.find("Name").text
        print(f"   -> Applying secure config for Wifi: '{name}'...")

        # Hàm con để cập nhật hoặc thêm thẻ nếu chưa có
        def set_node_value(parent, tag, value):
            child = parent.find(tag)
            if child is None:
                child = ET.SubElement(parent, tag)
            child.text = value

        # Cập nhật các thông số bảo mật theo chuẩn CIS
        set_node_value(net, "SecurityMode", "WPA2Personal")
        set_node_value(net, "Encryption", "AES(secure)")
        set_node_value(net, "ClientIsolation", "Enabled")
        set_node_value(net, "TimeBasedAccess", "Enabled")
        set_node_value(net, "Passphrase", "DoAnTotNghiep@2025") # Pass mặc định an toàn

        # Chuyển đổi Node XML đã sửa thành chuỗi string để gửi đi
        fix_xml = ET.tostring(net, encoding='unicode')
        
        if client.set_config(fix_xml):
            print(f"      Success.")
        else:
            print(f"      Failed.")