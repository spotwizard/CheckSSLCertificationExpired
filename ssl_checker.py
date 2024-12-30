import ssl
import socket
import datetime
import json
import colorama
from colorama import Fore, Style
from typing import Dict, Tuple

# 初始化 colorama，支援 Windows 系統的顏色輸出
colorama.init()

def check_ssl_expiry(domain: str) -> Tuple[datetime.datetime, bool, str]:
    """
    檢查網域的 SSL 憑證狀態
    返回：(過期日期, 是否過期, 錯誤訊息)
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                is_expired = expiry_date < datetime.datetime.now()
                return expiry_date, is_expired, ""
    except socket.gaierror:
        return None, None, "域名解析失敗"
    except socket.timeout:
        return None, None, "連線超時"
    except ssl.SSLError as e:
        return None, None, f"SSL 錯誤: {str(e)}"
    except Exception as e:
        return None, None, f"未知錯誤: {str(e)}"

def load_config(file_path: str = 'domains.json') -> list:
    """
    載入設定檔
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            return config.get('domains', [])
    except FileNotFoundError:
        print(f"{Fore.RED}錯誤: 找不到設定檔 {file_path}{Style.RESET_ALL}")
        return []
    except json.JSONDecodeError:
        print(f"{Fore.RED}錯誤: 設定檔格式不正確{Style.RESET_ALL}")
        return []

def main():
    print(f"{Fore.CYAN}開始檢查 SSL 憑證狀態...{Style.RESET_ALL}")
    print("-" * 70)
    
    domains = load_config()
    if not domains:
        print(f"{Fore.RED}錯誤: 沒有找到要檢查的網域{Style.RESET_ALL}")
        return

    for domain in domains:
        print(f"檢查網域: {Fore.YELLOW}{domain}{Style.RESET_ALL}")
        expiry_date, is_expired, error = check_ssl_expiry(domain)
        
        if error:
            print(f"{Fore.RED}錯誤: {error}{Style.RESET_ALL}")
        else:
            days_remaining = (expiry_date - datetime.datetime.now()).days
            status_color = Fore.RED if is_expired else Fore.GREEN
            status_text = "已過期" if is_expired else "有效"
            
            print(f"憑證狀態: {status_color}{status_text}{Style.RESET_ALL}")
            print(f"過期時間: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"剩餘天數: {status_color}{days_remaining}{Style.RESET_ALL} 天")
        
        print("-" * 70)

if __name__ == "__main__":
    main()
