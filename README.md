Comprehensive vulnerability detection:
- SQL Injection (Error, Union, Boolean, Time-based)
- XSS (Reflected, Stored, DOM-based)
- IDOR (Insecure Direct Object Reference)
- Authentication Bypass
- Authorization Issues
- CSRF (Cross-Site Request Forgery)
- Directory Traversal / LFI / RFI
- Open Redirect
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- Command Injection
- Account Takeover
- Admin Panel Discovery
- API Security Issues
- JWT Token Vulnerabilities
- Session Management Issues
- CORS Misconfiguration
- Security Headers
- Information Disclosure


# Basit kullanım
python han.py http://example.com

# Login Sayfası
python han.py "http://site.com/login.php" --output login_scan.json

# URL parametreleri ile
python han.py "http://example.com/page.php?id=1"
python han.py "http://company.com/portal/user.php?user_id=1" --threads 15

# Multi-threaded (20 thread)
python han.py http://example.com --threads 20

# JSON rapor ile
python han.py http://example.com --output report.json

# Custom timeout
python han.py http://example.com --timeout 15

# Quiet mode
python han.py http://example.com --quiet

# Tam profesyonel tarama
python han.py "http://example.com/login.php" --threads 20 --timeout 15 --output scan_report.json
