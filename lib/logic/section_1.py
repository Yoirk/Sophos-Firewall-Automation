import xml.etree.ElementTree as ET

def check_1_1_1_idle_timeout(client):
    xml = client.get_config("AdminSettings")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    # --- 1. Kiểm tra Idle Timeout (Yêu cầu: <= 10 phút) ---
    logout_node = root.find(".//LoginSecurity/LogoutSession")
    logout_val = logout_node.text if logout_node is not None else "Disable"
    
    try:
        is_logout_ok = (logout_val != "Disable" and int(logout_val) <= 10)
    except ValueError:
        is_logout_ok = False

    # --- 2. Kiểm tra Block Login (Yêu cầu: Enable) ---
    block_node = root.find(".//LoginSecurity/BlockLogin")
    block_val = block_node.text if block_node is not None else "Disable"
    is_block_enabled = (block_val == "Enable")

    # --- 3. Kiểm tra Thông số Block (CIS: 5 lần, trong 60s, khóa >= 5 phút) ---
    # Lưu ý: Code dưới đây kiểm tra chặt chẽ theo CIS
    atm_node = root.find(".//BlockLoginSettings/UnsucccessfulAttempt")
    dur_node = root.find(".//BlockLoginSettings/Duration")
    min_node = root.find(".//BlockLoginSettings/ForMinutes")

    # Giá trị mặc định nếu không tìm thấy thẻ
    a_val = int(atm_node.text) if atm_node is not None else 0
    d_val = int(dur_node.text) if dur_node is not None else 0
    t_val = int(min_node.text) if min_node is not None else 0

    # Điều kiện: Số lần thử <= 5, Trong vòng <= 60s, Khóa >= 5 phút
    is_params_ok = (a_val > 0 and a_val <= 5) and (d_val > 0 and d_val <= 60) and (t_val >= 5)

    # TỔNG HỢP KẾT QUẢ
    if is_logout_ok and is_block_enabled and is_params_ok:
        return True, f"Timeout:{logout_val}m, Block:{block_val}"
    else:
        # Trả về chi tiết lỗi để dễ debug
        details = []
        if not is_logout_ok: details.append(f"Timeout:{logout_val}")
        if not is_block_enabled: details.append(f"Block:{block_val}")
        if not is_params_ok: details.append(f"Params({a_val}/{d_val}/{t_val}) invalid")
        
        return False, f"FAIL: {', '.join(details)}"

def check_1_1_2_login_disclaimer(client):
    xml = client.get_config("AdminSettings")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)
    node = root.find(".//LoginDisclaimer")
    val = node.text if node is not None else "Disable"
    return (val == "Enable"), val

def check_1_1_3_ntp(client):
    xml = client.get_config("Time")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)
    
    # 1. Kiểm tra TimeZone
    tz_node = root.find(".//TimeZone")
    tz = tz_node.text if tz_node is not None else "Unknown"
    
    # 2. Kiểm tra Custom NTP Server
    ntp_node = root.find(".//CustomNTPServer/NTPServer")
    server_val = ntp_node.text if ntp_node is not None else "None"

    # Điều kiện Pass:
    is_tz_ok = (tz == "Asia/Ho_Chi_Minh")
    # Kiểm tra xem server có đúng là cái muốn không
    is_server_ok = ("time.windows.com" in server_val)
    
    if is_tz_ok and is_server_ok:
        return True, f"Correct (TZ:{tz}, Server:{server_val})"
    else:
        return False, f"Incorrect (TZ:{tz}, Server:{server_val})"

def check_1_1_5_password_complexity(client):
    xml = client.get_config("AdminSettings")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    # 1. Kiểm tra nút tổng (Master Switch)
    chk_node = root.find(".//PasswordComplexitySettings/PasswordComplexityCheck")
    is_master_enabled = (chk_node.text == "Enable") if chk_node is not None else False

    # 2. Kiểm tra các tham số chi tiết
    # Lấy node gốc của phần complexity để tìm cho gọn
    comp_root = root.find(".//PasswordComplexitySettings/PasswordComplexity")
    
    if comp_root is None:
        return False, "Missing Complexity Settings"

    # a. Kiểm tra độ dài
    min_len_enable = comp_root.find("MinimumPasswordLength")
    min_len_val = comp_root.find("MinimumPasswordLengthValue")
    
    is_len_on = (min_len_enable.text == "Enable") if min_len_enable is not None else False
    actual_len = 0
    if min_len_val is not None and min_len_val.text:
        try:
            actual_len = int(min_len_val.text)
        except ValueError:
            actual_len = 0
            
    # length tùy chính sách
    is_len_ok = is_len_on and (actual_len >= 8)

    # b. Kiểm tra ký tự đặc biệt
    spec_node = comp_root.find("IncludeSpecialCharacter")
    is_spec_ok = (spec_node.text == "Enable") if spec_node is not None else False

    # c. Kiểm tra chữ cái và số (Bổ sung cho chặt chẽ)
    alpha_node = comp_root.find("IncludeAlphabeticCharacters")
    num_node = comp_root.find("IncludeNumericCharacter")
    is_alpha_ok = (alpha_node.text == "Enable") if alpha_node is not None else False
    is_num_ok = (num_node.text == "Enable") if num_node is not None else False

    # --- TỔNG HỢP ---
    if is_master_enabled and is_len_ok and is_spec_ok and is_alpha_ok and is_num_ok:
        return True, f"Len:{actual_len}, Special:On, Alpha:On, Num:On"
    else:
        details = []
        if not is_master_enabled: details.append("MasterSwitch:Off")
        if not is_len_ok: details.append(f"MinLen:{'On' if is_len_on else 'Off'}(Val:{actual_len})")
        if not is_spec_ok: details.append("SpecialChar:Off")
        if not is_alpha_ok: details.append("Alpha:Off")
        if not is_num_ok: details.append("Numeric:Off")
        return False, f"{', '.join(details)}"

def check_1_1_6_wan_access(client):
    xml = client.get_config("Zone")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)
    
    # Các dịch vụ bắt buộc phải TẮT trên WAN theo chuẩn CIS
    forbidden_services = {
        "HTTPS": ".//ApplianceAccess/AdminServices/HTTPS",
        "SSH": ".//ApplianceAccess/AdminServices/SSH",
        "Ping": ".//ApplianceAccess/NetworkServices/Ping",
        "DNS": ".//ApplianceAccess/NetworkServices/DNS",
        "SNMP": ".//ApplianceAccess/OtherServices/SNMP",
        "SMTPRelay": ".//ApplianceAccess/OtherServices/SMTPRelay"
    }

    zones = root.findall(".//Zone")
    violations = []

    for zone in zones:
        z_type = zone.find("Type")
        # Chỉ kiểm tra vùng WAN
        if z_type is not None and z_type.text == "WAN":
            zone_name = zone.find("Name").text
            
            for svc_name, xpath in forbidden_services.items():
                node = zone.find(xpath)
                val = node.text if node is not None else "Disable"
                
                # Nếu dịch vụ đang Bật -> Vi phạm
                if val == "Enable":
                    violations.append(f"{zone_name}:{svc_name}")

    if violations:
        return False, f"WAN exposes: {', '.join(violations)}"
    
    return True, "WAN Access Disabled"