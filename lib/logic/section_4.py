import xml.etree.ElementTree as ET

def check_4_2_pattern_update(client):
    xml = client.get_config("PatternDownload")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    # Check lỗi API
    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"

    # 1. Kiểm tra Auto Update
    auto_node = root.find(".//AutoUpdate")
    if auto_node is None:
        return False, "Missing XML Tag <AutoUpdate>"
    
    is_auto_on = (auto_node.text == "On")

    # 2. Kiểm tra Interval (15 phút)
    int_node = root.find(".//Interval")
    if int_node is None:
        return False, "Missing XML Tag <Interval>"
    
    int_val = int_node.text
    # Kiểm tra chuỗi "15 minutes"
    is_interval_ok = "15 minutes" in int_val.lower()

    if is_auto_on and is_interval_ok:
        return True, f"Auto:{auto_node.text}, Interval:{int_val})"
    else:
        return False, f"Auto:{auto_node.text}, Interval:{int_val})"

def check_4_3_auto_hotfix(client):
    xml = client.get_config("Hotfix")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)
    val = root.find(".//AllowAutoInstallOfHotFixes").text
    return (val == "Enable"), val

def check_4_4_backup(client):
    xml = client.get_config("BackupRestore")
    if not xml: return False, "No Connection"
    root = ET.fromstring(xml)

    if root.tag == "Response" and root.find("Status") is not None:
        return False, f"API Error: {root.find('Status').text}"

    # Tìm node BackupMode
    mode_node = root.find(".//ScheduleBackup/BackupMode")
    val = mode_node.text if mode_node is not None else "Local"

    # Tìm node Frequency
    freq_node = root.find(".//ScheduleBackup/BackupFrequency")
    freq_val = freq_node.text if freq_node is not None else "Never"

    # Điều kiện Pass: Mode là FTP hoặc Mail VÀ Frequency không phải là Never
    is_mode_ok = val in ["FTP", "Mail"]
    is_freq_ok = freq_val in ["Daily", "Weekly", "Monthly"]

    if is_mode_ok and is_freq_ok:
        return True, f"Mode:{val}, Freq:{freq_val})"
    else:
        return False, f"Mode:{val}, Freq:{freq_val})"