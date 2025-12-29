import requests
import urllib3
import os
import time
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SophosClient:
    def __init__(self, ip=None, port=None, user=None, password=None):
        # Ưu tiên lấy từ tham số (Ansible truyền vào), nếu không có thì lấy từ .env
        self.ip = ip or os.getenv("SOPHOS_IP")
        self.port = port or os.getenv("SOPHOS_PORT")
        self.user = user or os.getenv("SOPHOS_USER")
        self.password = password or os.getenv("SOPHOS_PASSWORD")
        
        if self.ip and self.port:
            self.base_url = f"https://{self.ip}:{self.port}/webconsole/APIController"
        else:
            self.base_url = None
            print("Warning: IP or Port missing.")

    def _send(self, xml_body):
        if not self.password: return None
        payload = f"""<Request><Login><Username>{self.user}</Username><Password>{self.password}</Password></Login>{xml_body}</Request>"""
        try:
            res = requests.post(self.base_url, data={'reqxml': payload}, verify=False, timeout=60)
            return res.text
        except Exception as e:
            print(f"Connection Error: {e}")
            return None

    def get_config(self, entity):
        return self._send(f"<Get><{entity}/></Get>")
    
    def set_config(self, xml_content):
        res = self._send(f"<Set>{xml_content}</Set>")
        
        # Kiểm tra thành công
        if res and 'Configuration applied successfully' in res:
            return True
        
        # --- THÊM ĐOẠN DEBUG NÀY ---
        print(f"\n[DEBUG] XML Gửi đi: {xml_content}")
        print(f"[DEBUG] Lỗi trả về từ Firewall: {res}\n")
        # ---------------------------
        
        return False