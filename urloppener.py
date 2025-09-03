#!/usr/bin/env python3
"""
Advanced Web Security Scanner
A comprehensive web security assessment tool with modern GUI
Author: Security Assessment Tool
Version: 2.0
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import ssl
import socket
import subprocess
import json
import re
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
import dns.resolver
import whois
from bs4 import BeautifulSoup
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import concurrent.futures
import webbrowser
from pathlib import Path

class WebSecurityScanner:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.vulnerabilities = []
        self.security_score = 0
        self.total_checks = 0
        self.passed_checks = 0
        
    def setup_ui(self):
        """Setup modern, futuristic GUI"""
        self.root.title("🔒 Advanced Web Security Scanner v2.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0f')
        
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark theme colors
        style.configure('Title.TLabel', 
                       background='#0a0a0f', 
                       foreground='#00ff88', 
                       font=('Segoe UI', 24, 'bold'))
        
        style.configure('Subtitle.TLabel', 
                       background='#0a0a0f', 
                       foreground='#ffffff', 
                       font=('Segoe UI', 12))
        
        style.configure('Modern.TFrame', 
                       background='#1a1a2e', 
                       relief='flat', 
                       borderwidth=1)
        
        style.configure('Cyber.TButton',
                       background='#16213e',
                       foreground='#00ff88',
                       font=('Segoe UI', 10, 'bold'),
                       focuscolor='none')
        
        style.map('Cyber.TButton',
                 background=[('active', '#0f3460'),
                           ('pressed', '#00ff88')])
        
        # Main container
        main_frame = ttk.Frame(self.root, style='Modern.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title section
        title_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(title_frame, 
                               text="🔒 ADVANCED WEB SECURITY SCANNER", 
                               style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, 
                                  text="Comprehensive Security Assessment & Vulnerability Detection",
                                  style='Subtitle.TLabel')
        subtitle_label.pack(pady=(5, 0))
        
        # Input section
        input_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        url_frame = ttk.Frame(input_frame)
        url_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(url_frame, text="Target URL:", 
                 background='#1a1a2e', foreground='#ffffff',
                 font=('Segoe UI', 12, 'bold')).pack(anchor=tk.W)
        
        self.url_entry = tk.Entry(url_frame, 
                                 font=('Segoe UI', 12),
                                 bg='#16213e', 
                                 fg='#ffffff',
                                 insertbackground='#00ff88',
                                 relief='flat',
                                 bd=10)
        self.url_entry.pack(fill=tk.X, pady=(5, 0), ipady=8)
        self.url_entry.insert(0, "https://example.com")
        
        # Buttons frame
        buttons_frame = ttk.Frame(input_frame)
        buttons_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_button = ttk.Button(buttons_frame, 
                                     text="🚀 START SECURITY SCAN",
                                     style='Cyber.TButton',
                                     command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10), ipadx=20, ipady=5)
        
        self.export_button = ttk.Button(buttons_frame, 
                                       text="📄 EXPORT REPORT",
                                       style='Cyber.TButton',
                                       command=self.export_report,
                                       state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=(0, 10), ipadx=20, ipady=5)
        
        self.clear_button = ttk.Button(buttons_frame, 
                                      text="🗑️ CLEAR",
                                      style='Cyber.TButton',
                                      command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, ipadx=20, ipady=5)
        
        # Progress section
        progress_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        progress_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        self.progress_label = ttk.Label(progress_frame, 
                                       text="Ready to scan...",
                                       background='#1a1a2e', 
                                       foreground='#00ff88',
                                       font=('Segoe UI', 10))
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                           variable=self.progress_var,
                                           maximum=100,
                                           style='TProgressbar')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Results section
        results_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Results tab
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="📊 Security Report")
        
        self.results_text = scrolledtext.ScrolledText(self.results_tab,
                                                     bg='#0f0f23',
                                                     fg='#ffffff',
                                                     font=('Consolas', 10),
                                                     insertbackground='#00ff88',
                                                     selectbackground='#16213e')
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Vulnerabilities tab
        self.vuln_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_tab, text="🚨 Vulnerabilities")
        
        self.vuln_tree = ttk.Treeview(self.vuln_tab, 
                                     columns=('Severity', 'Description', 'Risk'),
                                     show='tree headings')
        self.vuln_tree.heading('#0', text='Vulnerability Type')
        self.vuln_tree.heading('Severity', text='Severity')
        self.vuln_tree.heading('Description', text='Description')
        self.vuln_tree.heading('Risk', text='Risk Level')
        self.vuln_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Score display
        score_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        score_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.score_label = ttk.Label(score_frame,
                                    text="Security Score: --/100",
                                    background='#1a1a2e',
                                    foreground='#00ff88',
                                    font=('Segoe UI', 14, 'bold'))
        self.score_label.pack()
        
    def log_message(self, message, level="INFO"):
        """Log messages with timestamp and color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "ERROR":
            color_code = "🔴"
        elif level == "WARNING":
            color_code = "🟡"
        elif level == "SUCCESS":
            color_code = "🟢"
        elif level == "CRITICAL":
            color_code = "🔥"
        else:
            color_code = "ℹ️"
            
        formatted_message = f"[{timestamp}] {color_code} {message}\n"
        
        self.results_text.insert(tk.END, formatted_message)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_progress(self, value, message):
        """Update progress bar and message"""
        self.progress_var.set(value)
        self.progress_label.config(text=message)
        self.root.update_idletasks()
        
    def start_scan_thread(self):
        """Start scanning in a separate thread"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scan")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
        
        self.scan_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        self.clear_results()
        
        # Reset counters
        self.vulnerabilities = []
        self.total_checks = 0
        self.passed_checks = 0
        
        thread = threading.Thread(target=self.perform_security_scan, args=(url,))
        thread.daemon = True
        thread.start()
        
    def perform_security_scan(self, url):
        """Comprehensive security scan"""
        try:
            self.log_message("=" * 60, "INFO")
            self.log_message(f"Starting comprehensive security scan for: {url}", "INFO")
            self.log_message("=" * 60, "INFO")
            
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Security checks
            checks = [
                ("SSL/TLS Certificate Analysis", self.check_ssl_security, url),
                ("HTTP Security Headers", self.check_security_headers, url),
                ("DNS Security Configuration", self.check_dns_security, domain),
                ("Domain Information", self.check_domain_info, domain),
                ("Content Security Analysis", self.check_content_security, url),
                ("Server Information Disclosure", self.check_server_disclosure, url),
                ("Common Vulnerabilities", self.check_common_vulnerabilities, url),
                ("OWASP Top 10 Checks", self.check_owasp_top10, url),
                ("Privacy & Tracking Analysis", self.check_privacy_tracking, url),
                ("Performance Security", self.check_performance_security, url)
            ]
            
            total_steps = len(checks)
            
            for i, (check_name, check_function, check_param) in enumerate(checks):
                try:
                    self.update_progress((i / total_steps) * 100, f"Running: {check_name}")
                    self.log_message(f"\n🔍 {check_name}", "INFO")
                    self.log_message("-" * 40, "INFO")
                    
                    check_function(check_param)
                    time.sleep(0.5)  # Prevent rate limiting
                    
                except Exception as e:
                    self.log_message(f"Error in {check_name}: {str(e)}", "ERROR")
                    
            # Calculate final security score
            self.calculate_security_score()
            self.update_progress(100, "Security scan completed!")
            
            # Update UI
            self.populate_vulnerabilities_tree()
            self.scan_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.NORMAL)
            
        except Exception as e:
            self.log_message(f"Scan failed: {str(e)}", "ERROR")
            self.scan_button.config(state=tk.NORMAL)
            
    def check_ssl_security(self, url):
        """Comprehensive SSL/TLS security analysis"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if parsed_url.scheme != 'https':
                self.add_vulnerability("SSL/TLS", "CRITICAL", 
                                     "No HTTPS encryption", "Site uses insecure HTTP")
                self.log_message("❌ CRITICAL: Site not using HTTPS", "CRITICAL")
                return
            
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Check certificate validity
            now = datetime.now()
            not_after = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - now).days
            
            if days_until_expiry < 0:
                self.add_vulnerability("SSL Certificate", "CRITICAL",
                                     "Expired certificate", "SSL certificate has expired")
                self.log_message("❌ CRITICAL: SSL certificate expired", "CRITICAL")
            elif days_until_expiry < 30:
                self.add_vulnerability("SSL Certificate", "HIGH",
                                     "Certificate expiring soon", f"Expires in {days_until_expiry} days")
                self.log_message(f"⚠️ WARNING: Certificate expires in {days_until_expiry} days", "WARNING")
            else:
                self.log_message(f"✅ Certificate valid until {not_after}", "SUCCESS")
                self.passed_checks += 1
                
            # Check cipher strength
            if cipher:
                cipher_name = cipher[0]
                if 'RC4' in cipher_name or 'DES' in cipher_name:
                    self.add_vulnerability("SSL Cipher", "HIGH",
                                         "Weak cipher suite", f"Using weak cipher: {cipher_name}")
                    self.log_message(f"❌ Weak cipher detected: {cipher_name}", "ERROR")
                else:
                    self.log_message(f"✅ Strong cipher: {cipher_name}", "SUCCESS")
                    self.passed_checks += 1
                    
            # Check certificate chain
            issuer = cert_info.get('issuer', [])
            for item in issuer:
                if item[0][0] == 'organizationName':
                    self.log_message(f"✅ Certificate issued by: {item[0][1]}", "SUCCESS")
                    break
                    
            self.total_checks += 3
            
        except Exception as e:
            self.log_message(f"SSL check failed: {str(e)}", "ERROR")
            self.add_vulnerability("SSL/TLS", "HIGH", "SSL analysis failed", str(e))
            
    def check_security_headers(self, url):
        """Check for security headers"""
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': ('HSTS not enabled', 'Missing HSTS header'),
                'Content-Security-Policy': ('No CSP', 'Missing Content Security Policy'),
                'X-Content-Type-Options': ('MIME sniffing possible', 'Missing X-Content-Type-Options'),
                'X-Frame-Options': ('Clickjacking possible', 'Missing X-Frame-Options'),
                'X-XSS-Protection': ('XSS protection disabled', 'Missing X-XSS-Protection'),
                'Referrer-Policy': ('Information leakage', 'Missing Referrer-Policy'),
                'Feature-Policy': ('Feature policy not set', 'Missing Feature-Policy')
            }
            
            for header, (vuln_desc, vuln_detail) in security_headers.items():
                if header in headers:
                    self.log_message(f"✅ {header}: {headers[header]}", "SUCCESS")
                    self.passed_checks += 1
                else:
                    self.log_message(f"❌ Missing: {header}", "ERROR")
                    self.add_vulnerability("Security Headers", "MEDIUM", vuln_desc, vuln_detail)
                    
                self.total_checks += 1
                
            # Check for information disclosure headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in disclosure_headers:
                if header in headers:
                    self.log_message(f"⚠️ Information disclosure: {header}: {headers[header]}", "WARNING")
                    self.add_vulnerability("Information Disclosure", "LOW", 
                                         f"{header} header present", f"Server reveals: {headers[header]}")
                    
        except Exception as e:
            self.log_message(f"Header check failed: {str(e)}", "ERROR")
            
    def check_dns_security(self, domain):
        """Check DNS security configuration"""
        try:
            # Check for DNSSEC
            try:
                resolver = dns.resolver.Resolver()
                resolver.use_edns(0, dns.flags.DO, 4096)
                answer = resolver.resolve(domain, 'A')
                if answer.response.flags & dns.flags.AD:
                    self.log_message("✅ DNSSEC validation successful", "SUCCESS")
                    self.passed_checks += 1
                else:
                    self.log_message("❌ DNSSEC not properly configured", "ERROR")
                    self.add_vulnerability("DNS Security", "MEDIUM", 
                                         "DNSSEC not configured", "Domain not protected by DNSSEC")
            except:
                self.log_message("❌ DNSSEC check failed", "ERROR")
                
            # Check SPF records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                spf_found = False
                for record in txt_records:
                    if record.to_text().startswith('"v=spf1'):
                        spf_found = True
                        self.log_message(f"✅ SPF record found: {record.to_text()}", "SUCCESS")
                        self.passed_checks += 1
                        break
                        
                if not spf_found:
                    self.log_message("❌ No SPF record found", "ERROR")
                    self.add_vulnerability("Email Security", "MEDIUM",
                                         "Missing SPF record", "Email spoofing possible")
                    
            except:
                self.log_message("❌ SPF check failed", "ERROR")
                
            # Check DMARC records
            try:
                dmarc_domain = f"_dmarc.{domain}"
                txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                for record in txt_records:
                    if 'v=DMARC1' in record.to_text():
                        self.log_message(f"✅ DMARC record found: {record.to_text()}", "SUCCESS")
                        self.passed_checks += 1
                        break
                else:
                    self.log_message("❌ No DMARC record found", "ERROR")
                    self.add_vulnerability("Email Security", "MEDIUM",
                                         "Missing DMARC record", "Email authentication weak")
            except:
                self.log_message("❌ DMARC check failed", "ERROR")
                
            self.total_checks += 3
            
        except Exception as e:
            self.log_message(f"DNS security check failed: {str(e)}", "ERROR")
            
    def check_domain_info(self, domain):
        """Check domain information and reputation"""
        try:
            # Domain whois information
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                        
                    domain_age = (datetime.now() - creation_date).days
                    self.log_message(f"✅ Domain age: {domain_age} days", "SUCCESS")
                    
                    if domain_age < 30:
                        self.add_vulnerability("Domain Reputation", "MEDIUM",
                                             "Very new domain", "Domain registered recently")
                        self.log_message("⚠️ Very new domain - potential risk", "WARNING")
                        
                if domain_info.expiration_date:
                    if isinstance(domain_info.expiration_date, list):
                        expiration_date = domain_info.expiration_date[0]
                    else:
                        expiration_date = domain_info.expiration_date
                        
                    days_until_expiry = (expiration_date - datetime.now()).days
                    if days_until_expiry < 30:
                        self.add_vulnerability("Domain Management", "LOW",
                                             "Domain expiring soon", f"Expires in {days_until_expiry} days")
                        
                self.passed_checks += 1
                
            except Exception as e:
                self.log_message(f"Whois lookup failed: {str(e)}", "ERROR")
                
            self.total_checks += 1
            
        except Exception as e:
            self.log_message(f"Domain info check failed: {str(e)}", "ERROR")
            
    def check_content_security(self, url):
        """Check content security issues"""
        try:
            response = self.session.get(url, timeout=15)
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for mixed content
            if url.startswith('https://'):
                http_links = soup.find_all(['img', 'script', 'link'], src=re.compile(r'^http://'))
                if http_links:
                    self.add_vulnerability("Mixed Content", "MEDIUM",
                                         "HTTP resources on HTTPS page", f"Found {len(http_links)} insecure resources")
                    self.log_message(f"❌ Mixed content found: {len(http_links)} resources", "ERROR")
                else:
                    self.log_message("✅ No mixed content detected", "SUCCESS")
                    self.passed_checks += 1
                    
            # Check for external JavaScript
            external_scripts = []
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src')
                if src and not src.startswith('/') and urlparse(url).netloc not in src:
                    external_scripts.append(src)
                    
            if external_scripts:
                self.log_message(f"⚠️ External scripts found: {len(external_scripts)}", "WARNING")
                for script in external_scripts[:5]:  # Show first 5
                    self.log_message(f"   - {script}", "WARNING")
                    
            # Check for inline JavaScript
            inline_scripts = soup.find_all('script', src=False)
            inline_count = len([s for s in inline_scripts if s.string and s.string.strip()])
            if inline_count > 0:
                self.log_message(f"⚠️ Inline scripts found: {inline_count}", "WARNING")
                if inline_count > 10:
                    self.add_vulnerability("Content Security", "LOW",
                                         "Many inline scripts", "Consider using CSP with nonces")
                    
            # Check for forms without CSRF protection
            forms = soup.find_all('form')
            vulnerable_forms = 0
            for form in forms:
                csrf_tokens = form.find_all(['input'], attrs={'name': re.compile(r'csrf|token', re.I)})
                if not csrf_tokens:
                    vulnerable_forms += 1
                    
            if vulnerable_forms > 0:
                self.add_vulnerability("CSRF Protection", "MEDIUM",
                                     "Forms without CSRF tokens", f"{vulnerable_forms} forms lack CSRF protection")
                self.log_message(f"❌ Forms without CSRF protection: {vulnerable_forms}", "ERROR")
            else:
                self.log_message("✅ CSRF protection appears adequate", "SUCCESS")
                self.passed_checks += 1
                
            self.total_checks += 3
            
        except Exception as e:
            self.log_message(f"Content security check failed: {str(e)}", "ERROR")
            
    def check_server_disclosure(self, url):
        """Check for server information disclosure"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for directory listing
            test_paths = ['/admin/', '/test/', '/backup/', '/.git/', '/.env', '/wp-admin/']
            disclosed_paths = []
            
            for path in test_paths:
                try:
                    test_url = urljoin(url, path)
                    test_response = self.session.head(test_url, timeout=5)
                    if test_response.status_code == 200:
                        disclosed_paths.append(path)
                except:
                    pass
                    
            if disclosed_paths:
                self.add_vulnerability("Information Disclosure", "MEDIUM",
                                     "Sensitive paths accessible", f"Paths found: {', '.join(disclosed_paths)}")
                self.log_message(f"❌ Sensitive paths found: {', '.join(disclosed_paths)}", "ERROR")
            else:
                self.log_message("✅ No obvious sensitive paths found", "SUCCESS")
                self.passed_checks += 1
                
            # Check for error page information disclosure
            error_url = urljoin(url, '/nonexistent-page-' + str(int(time.time())))
            try:
                error_response = self.session.get(error_url, timeout=5)
                error_content = error_response.text.lower()
                
                disclosure_indicators = ['apache', 'nginx', 'php', 'mysql', 'server version', 'stack trace']
                found_indicators = [indicator for indicator in disclosure_indicators if indicator in error_content]
                
                if found_indicators:
                    self.add_vulnerability("Information Disclosure", "LOW",
                                         "Server info in error pages", f"Revealed: {', '.join(found_indicators)}")
                    self.log_message(f"⚠️ Server information disclosed in error pages", "WARNING")
                else:
                    self.log_message("✅ Error pages don't reveal server info", "SUCCESS")
                    self.passed_checks += 1
                    
            except:
                pass
                
            self.total_checks += 2
            
        except Exception as e:
            self.log_message(f"Server disclosure check failed: {str(e)}", "ERROR")
            
    def check_common_vulnerabilities(self, url):
        """Check for common vulnerabilities"""
        try:
            # Check for SQL injection indicators (basic)
            sql_test_params = ["'", '"', "1' OR '1'='1", "1; DROP TABLE"]
            for param in sql_test_params:
                try:
                    test_url = f"{url}?test={param}"
                    response = self.session.get(test_url, timeout=5)
                    
                    sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft jet database']
                    for error in sql_errors:
                        if error in response.text.lower():
                            self.add_vulnerability("SQL Injection", "HIGH",
                                                 "Possible SQL injection", "SQL error messages detected")
                            self.log_message("❌ Possible SQL injection vulnerability", "ERROR")
                            return
                except:
                    pass
                    
            self.log_message("✅ No obvious SQL injection vulnerabilities", "SUCCESS")
            
            # Check for XSS reflection (basic)
            xss_payload = "<script>alert('xss')</script>"
            try:
                test_url = f"{url}?test={xss_payload}"
                response = self.session.get(test_url, timeout=5)
                
                if xss_payload in response.text:
                    self.add_vulnerability("Cross-Site Scripting", "HIGH",
                                         "Reflected XSS possible", "User input reflected without sanitization")
                    self.log_message("❌ Possible reflected XSS vulnerability", "ERROR")
                else:
                    self.log_message("✅ No obvious XSS reflection", "SUCCESS")
                    self.passed_checks += 1
                    
            except:
                pass
                
            self.total_checks += 2
            
        except Exception as e:
            self.log_message(f"Common vulnerability check failed: {str(e)}", "ERROR")
            
    def check_owasp_top10(self, url):
        """Check for OWASP Top 10 vulnerabilities"""
        try:
            response = self.session.get(url, timeout=10)
            
            # A01: Broken Access Control
            test_urls = [
                urljoin(url, '/admin'),
                urljoin(url, '/administrator'),
                urljoin(url, '/wp-admin'),
                urljoin(url, '/panel'),
                urljoin(url, '/dashboard')
            ]
            
            accessible_admin = []
            for test_url in test_urls:
                try:
                    admin_response = self.session.head(test_url, timeout=5)
                    if admin_response.status_code in [200, 302, 401]:
                        accessible_admin.append(test_url)
                except:
                    pass
                    
            if accessible_admin:
                self.add_vulnerability("OWASP A01", "HIGH",
                                     "Broken Access Control", f"Admin panels accessible: {len(accessible_admin)}")
                self.log_message(f"❌ Admin panels found: {len(accessible_admin)}", "ERROR")
            else:
                self.log_message("✅ No obvious admin panels accessible", "SUCCESS")
                self.passed_checks += 1
                
            # A02: Cryptographic Failures
            if not url.startswith('https://'):
                self.add_vulnerability("OWASP A02", "HIGH",
                                     "Cryptographic Failures", "No HTTPS encryption")
                self.log_message("❌ No HTTPS - cryptographic failure", "ERROR")
            else:
                self.passed_checks += 1
                
            # A03: Injection (already covered in common_vulnerabilities)
            
            # A04: Insecure Design
            soup = BeautifulSoup(response.text, 'html.parser')
            password_fields = soup.find_all('input', {'type': 'password'})
            
            insecure_design_issues = 0
            for field in password_fields:
                form = field.find_parent('form')
                if form and not form.get('action', '').startswith('https://'):
                    insecure_design_issues += 1
                    
            if insecure_design_issues > 0:
                self.add_vulnerability("OWASP A04", "MEDIUM",
                                     "Insecure Design", "Password forms not using HTTPS")
                self.log_message("❌ Password forms not secure", "ERROR")
            else:
                self.passed_checks += 1
                
            # A05: Security Misconfiguration (covered in headers)
            
            # A06: Vulnerable Components
            try:
                server_header = response.headers.get('Server', '')
                powered_by = response.headers.get('X-Powered-By', '')
                
                vulnerable_versions = [
                    'Apache/2.2', 'Apache/2.0', 'nginx/1.0', 'nginx/1.1',
                    'PHP/5.', 'PHP/7.0', 'PHP/7.1'
                ]
                
                version_issues = []
                for version in vulnerable_versions:
                    if version in server_header or version in powered_by:
                        version_issues.append(version)
                        
                if version_issues:
                    self.add_vulnerability("OWASP A06", "MEDIUM",
                                         "Vulnerable Components", f"Outdated versions: {', '.join(version_issues)}")
                    self.log_message(f"⚠️ Potentially outdated components: {', '.join(version_issues)}", "WARNING")
                else:
                    self.passed_checks += 1
                    
            except:
                pass
                
            # A07: Identification and Authentication Failures
            login_forms = soup.find_all('form')
            auth_issues = 0
            
            for form in login_forms:
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    # Check for autocomplete on password fields
                    for field in password_fields:
                        if field.get('autocomplete') != 'off':
                            auth_issues += 1
                            break
                            
            if auth_issues > 0:
                self.add_vulnerability("OWASP A07", "MEDIUM",
                                     "Authentication Failures", "Password autocomplete not disabled")
                self.log_message("⚠️ Password autocomplete enabled", "WARNING")
            else:
                self.passed_checks += 1
                
            # A08: Software and Data Integrity Failures
            scripts = soup.find_all('script', src=True)
            external_scripts = [s for s in scripts if s.get('src') and 'http' in s.get('src')]
            integrity_protected = [s for s in external_scripts if s.get('integrity')]
            
            if external_scripts and len(integrity_protected) < len(external_scripts):
                unprotected = len(external_scripts) - len(integrity_protected)
                self.add_vulnerability("OWASP A08", "MEDIUM",
                                     "Data Integrity Failures", f"{unprotected} external scripts without integrity checks")
                self.log_message(f"⚠️ {unprotected} external scripts lack integrity protection", "WARNING")
            else:
                self.passed_checks += 1
                
            # A09: Security Logging and Monitoring Failures (hard to test externally)
            
            # A10: Server-Side Request Forgery (basic check)
            try:
                ssrf_test_url = f"{url}?url=http://127.0.0.1"
                ssrf_response = self.session.get(ssrf_test_url, timeout=5)
                
                if 'localhost' in ssrf_response.text or '127.0.0.1' in ssrf_response.text:
                    self.add_vulnerability("OWASP A10", "HIGH",
                                         "Server-Side Request Forgery", "Possible SSRF vulnerability detected")
                    self.log_message("❌ Possible SSRF vulnerability", "ERROR")
                else:
                    self.passed_checks += 1
                    
            except:
                pass
                
            self.total_checks += 8
            
        except Exception as e:
            self.log_message(f"OWASP Top 10 check failed: {str(e)}", "ERROR")
            
    def check_privacy_tracking(self, url):
        """Check for privacy and tracking issues"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for tracking scripts
            tracking_domains = [
                'google-analytics.com', 'googletagmanager.com', 'facebook.net',
                'doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com',
                'adsystem.amazon.com', 'scorecardresearch.com'
            ]
            
            scripts = soup.find_all('script', src=True)
            tracking_scripts = []
            
            for script in scripts:
                src = script.get('src', '')
                for domain in tracking_domains:
                    if domain in src:
                        tracking_scripts.append(domain)
                        break
                        
            if tracking_scripts:
                self.log_message(f"⚠️ Tracking scripts found: {len(set(tracking_scripts))}", "WARNING")
                for tracker in set(tracking_scripts):
                    self.log_message(f"   - {tracker}", "WARNING")
                    
                self.add_vulnerability("Privacy", "LOW",
                                     "Third-party tracking", f"Found {len(set(tracking_scripts))} tracking services")
            else:
                self.log_message("✅ No obvious tracking scripts detected", "SUCCESS")
                self.passed_checks += 1
                
            # Check for cookies
            cookies = response.cookies
            secure_cookies = 0
            httponly_cookies = 0
            
            for cookie in cookies:
                if cookie.secure:
                    secure_cookies += 1
                if cookie.has_nonstandard_attr('HttpOnly'):
                    httponly_cookies += 1
                    
            total_cookies = len(cookies)
            if total_cookies > 0:
                self.log_message(f"📊 Cookies: {total_cookies} total, {secure_cookies} secure, {httponly_cookies} HttpOnly", "INFO")
                
                if secure_cookies < total_cookies:
                    self.add_vulnerability("Cookie Security", "MEDIUM",
                                         "Insecure cookies", f"{total_cookies - secure_cookies} cookies not secure")
                    
                if httponly_cookies < total_cookies:
                    self.add_vulnerability("Cookie Security", "MEDIUM",
                                         "XSS-vulnerable cookies", f"{total_cookies - httponly_cookies} cookies accessible via JavaScript")
            else:
                self.log_message("✅ No cookies set", "SUCCESS")
                self.passed_checks += 1
                
            self.total_checks += 2
            
        except Exception as e:
            self.log_message(f"Privacy check failed: {str(e)}", "ERROR")
            
    def check_performance_security(self, url):
        """Check performance-related security issues"""
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=15)
            load_time = time.time() - start_time
            
            self.log_message(f"📊 Page load time: {load_time:.2f} seconds", "INFO")
            
            # Check response size
            content_length = len(response.content)
            self.log_message(f"📊 Response size: {content_length:,} bytes", "INFO")
            
            if content_length > 5 * 1024 * 1024:  # 5MB
                self.add_vulnerability("Performance", "LOW",
                                     "Large response size", f"Page size: {content_length:,} bytes")
                self.log_message("⚠️ Very large page size - potential DoS vector", "WARNING")
            else:
                self.passed_checks += 1
                
            # Check for compression
            content_encoding = response.headers.get('Content-Encoding', '')
            if content_encoding:
                self.log_message(f"✅ Content compression: {content_encoding}", "SUCCESS")
                self.passed_checks += 1
            elif content_length > 1024:  # Only warn for larger responses
                self.add_vulnerability("Performance", "LOW",
                                     "No content compression", "Missing gzip/deflate compression")
                self.log_message("⚠️ No content compression detected", "WARNING")
            else:
                self.passed_checks += 1
                
            # Check caching headers
            cache_headers = ['Cache-Control', 'Expires', 'ETag', 'Last-Modified']
            cache_found = any(header in response.headers for header in cache_headers)
            
            if cache_found:
                self.log_message("✅ Caching headers present", "SUCCESS")
                self.passed_checks += 1
            else:
                self.add_vulnerability("Performance", "LOW",
                                     "No caching headers", "Missing cache optimization")
                self.log_message("⚠️ No caching headers found", "WARNING")
                
            self.total_checks += 3
            
        except Exception as e:
            self.log_message(f"Performance check failed: {str(e)}", "ERROR")
            
    def add_vulnerability(self, category, severity, description, details):
        """Add vulnerability to list"""
        vulnerability = {
            'category': category,
            'severity': severity,
            'description': description,
            'details': details
        }
        self.vulnerabilities.append(vulnerability)
        
    def calculate_security_score(self):
        """Calculate overall security score"""
        if self.total_checks == 0:
            self.security_score = 0
            return
            
        base_score = (self.passed_checks / self.total_checks) * 100
        
        # Penalty system based on vulnerability severity
        penalties = {
            'CRITICAL': 20,
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 2
        }
        
        total_penalty = 0
        for vuln in self.vulnerabilities:
            total_penalty += penalties.get(vuln['severity'], 0)
            
        self.security_score = max(0, base_score - total_penalty)
        
        # Update score display
        score_color = "#ff4444" if self.security_score < 50 else "#ffaa00" if self.security_score < 80 else "#00ff88"
        
        self.score_label.config(text=f"Security Score: {self.security_score:.1f}/100",
                               foreground=score_color)
        
        # Log final summary
        self.log_message("\n" + "=" * 60, "INFO")
        self.log_message("SECURITY ASSESSMENT SUMMARY", "INFO")
        self.log_message("=" * 60, "INFO")
        self.log_message(f"Overall Security Score: {self.security_score:.1f}/100", "INFO")
        self.log_message(f"Tests Passed: {self.passed_checks}/{self.total_checks}", "INFO")
        self.log_message(f"Vulnerabilities Found: {len(self.vulnerabilities)}", "INFO")
        
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] = severity_counts.get(vuln['severity'], 0) + 1
            
        for severity, count in severity_counts.items():
            self.log_message(f"  {severity}: {count}", "INFO")
            
        # Recommendations
        self.log_message("\n🔧 SECURITY RECOMMENDATIONS:", "INFO")
        if self.security_score < 50:
            self.log_message("❌ CRITICAL: Immediate security improvements required", "CRITICAL")
        elif self.security_score < 70:
            self.log_message("⚠️ MODERATE: Several security issues need attention", "WARNING")
        elif self.security_score < 90:
            self.log_message("✅ GOOD: Minor security improvements recommended", "SUCCESS")
        else:
            self.log_message("🎉 EXCELLENT: Strong security posture maintained", "SUCCESS")
            
        self.log_message("=" * 60, "INFO")
        
    def populate_vulnerabilities_tree(self):
        """Populate vulnerabilities tree view"""
        # Clear existing items
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
            
        # Group vulnerabilities by category
        categories = {}
        for vuln in self.vulnerabilities:
            category = vuln['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(vuln)
            
        # Populate tree
        for category, vulns in categories.items():
            category_id = self.vuln_tree.insert('', 'end', text=f"📁 {category} ({len(vulns)})")
            
            for vuln in vulns:
                severity_icon = {
                    'CRITICAL': '🔥',
                    'HIGH': '🔴',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(vuln['severity'], '⚪')
                
                self.vuln_tree.insert(category_id, 'end',
                                    text=f"{severity_icon} {vuln['description']}",
                                    values=(vuln['severity'], vuln['details'], 
                                           self.get_risk_level(vuln['severity'])))
                                    
    def get_risk_level(self, severity):
        """Get risk level description"""
        risk_levels = {
            'CRITICAL': 'Immediate Action Required',
            'HIGH': 'High Priority Fix',
            'MEDIUM': 'Should Be Fixed',
            'LOW': 'Minor Improvement'
        }
        return risk_levels.get(severity, 'Unknown')
        
    def clear_results(self):
        """Clear all results"""
        self.results_text.delete(1.0, tk.END)
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        self.vulnerabilities = []
        self.security_score = 0
        self.total_checks = 0
        self.passed_checks = 0
        self.score_label.config(text="Security Score: --/100", foreground='#00ff88')
        self.progress_var.set(0)
        self.progress_label.config(text="Ready to scan...")
        self.export_button.config(state=tk.DISABLED)
        
    def export_report(self):
        """Export detailed security report"""
        if not self.vulnerabilities and self.security_score == 0:
            messagebox.showwarning("Warning", "No scan results to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Export as JSON
                    report_data = {
                        'timestamp': datetime.now().isoformat(),
                        'url': self.url_entry.get(),
                        'security_score': self.security_score,
                        'tests_passed': self.passed_checks,
                        'total_tests': self.total_checks,
                        'vulnerabilities': self.vulnerabilities
                    }
                    
                    with open(filename, 'w') as f:
                        json.dump(report_data, f, indent=2)
                else:
                    # Export as text
                    report_content = self.results_text.get(1.0, tk.END)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(report_content)
                        
                messagebox.showinfo("Success", f"Report exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")

def main():
    """Main application entry point"""
    root = tk.Tk()
    
    # Set application icon and properties
    root.iconname("Security Scanner")
    root.resizable(True, True)
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (1400 // 2)
    y = (root.winfo_screenheight() // 2) - (900 // 2)
    root.geometry(f"1400x900+{x}+{y}")
    
    # Create application
    app = WebSecurityScanner(root)
    
    # Handle window closing
    def on_closing():
        root.quit()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication terminated by user")
    except Exception as e:
        print(f"Application error: {e}")
        
if __name__ == "__main__":
    # Required dependencies check
    required_packages = [
        'requests', 'beautifulsoup4', 'dnspython', 'python-whois', 
        'cryptography', 'lxml'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'beautifulsoup4':
                import bs4
            elif package == 'dnspython':
                import dns.resolver
            elif package == 'python-whois':
                import whois
            else:
                __import__(package)
        except ImportError:
            missing_packages.append(package)
            
    if missing_packages:
        print("🚨 Missing required packages. Please install them using:")
        print(f"pip install {' '.join(missing_packages)}")
        print("\nFull installation command:")
        print("pip install requests beautifulsoup4 dnspython python-whois cryptography lxml")
        exit(1)
    else:
        main()