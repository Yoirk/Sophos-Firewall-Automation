import os
from datetime import datetime

def create_backup_session(ip):
    """
    Tạo cấu trúc thư mục backup: backups/<IP>/<YYYYMMDD_HHMMSS>/
    Trả về đường dẫn thư mục phiên làm việc hiện tại.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join("backups", ip, timestamp)
    
    try:
        os.makedirs(session_dir, exist_ok=True)
        print(f"\n[BACKUP] Created session directory: {session_dir}")
        return session_dir
    except OSError as e:
        print(f"[BACKUP] Error creating directory {session_dir}: {e}")
        return None

def save_snapshot(folder, filename, content):
    """
    Lưu nội dung XML vào file trong thư mục chỉ định.
    """
    if not folder or not content:
        return False
        
    file_path = os.path.join(folder, filename)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"   -> Snapshot saved: {filename}")
        return True
    except Exception as e:
        print(f"   -> [ERR] Could not save snapshot {filename}: {e}")
        return False