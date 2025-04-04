#!/usr/bin/env python3
import os
import subprocess
import re
import xml.etree.ElementTree as ET
import sys
import tempfile
import shutil
from pathlib import Path
import json
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class APKAnalyzer:
    def _init_(self, apk_path):
        self.apk_path = apk_path
        self.decompiled_dir = None
        self.findings = {
            "api_keys": [],
            "exported_activities": [],
            "webview_issues": [],
            "other_issues": []
        }
        self.app_name = os.path.basename(apk_path)
        self.scan_time = datetime.now()
        
    def print_banner(self):
        """Print a cool banner for the tool."""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║ {Fore.WHITE}█▀▀▄ █▀▀█ █▀▀█ ▀█▀ █▀▀▄    {Fore.RED}█▀▀ █▀▀ █▀▀▄ ▀▀█▀▀ ▀█▀ █▀▀▄ █▀▀ █{Fore.CYAN} ║
║ {Fore.WHITE}█  █ █▄▄▀ █  █  █  █  █    {Fore.RED}▀▀█ █▀▀ █  █   █    █  █  █ █▀▀ █{Fore.CYAN} ║
║ {Fore.WHITE}▀▀▀  ▀ ▀▀ ▀▀▀▀ ▀▀▀ ▀▀▀     {Fore.RED}▀▀▀ ▀▀▀ ▀  ▀   ▀   ▀▀▀ ▀  ▀ ▀▀▀ ▀▀▀▀{Fore.CYAN} ║
╚═══════════════════════════════════════════════════════════════╝
{Fore.GREEN}           Android APK Static Vulnerability Scanner {Style.RESET_ALL}
"""
        print(banner)
        print(f"{Fore.YELLOW}Target APK:{Style.RESET_ALL} {self.app_name}")
        print(f"{Fore.YELLOW}Scan started at:{Style.RESET_ALL} {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.YELLOW}Scanner version:{Style.RESET_ALL} 1.0.0\n")
        
    def check_apktool_installed(self):
        """Check if apktool is installed, if not, install it."""
        try:
            result = subprocess.run(["apktool", "--version"], capture_output=True, text=True)
            print(f"{Fore.GREEN}[+] apktool is installed:{Style.RESET_ALL} {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            print(f"{Fore.RED}[!] apktool not found. Attempting to install...{Style.RESET_ALL}")
            
            if sys.platform == "linux" or sys.platform == "linux2":
                try:
                    subprocess.run(["sudo", "apt-get", "update"], check=True)
                    subprocess.run(["sudo", "apt-get", "install", "-y", "apktool"], check=True)
                    print(f"{Fore.GREEN}[+] apktool installed successfully{Style.RESET_ALL}")
                    return True
                except subprocess.CalledProcessError:
                    print(f"{Fore.RED}[!] Failed to install apktool. Please install manually.{Style.RESET_ALL}")
                    return False
            elif sys.platform == "darwin":
                try:
                    subprocess.run(["brew", "install", "apktool"], check=True)
                    print(f"{Fore.GREEN}[+] apktool installed successfully{Style.RESET_ALL}")
                    return True
                except subprocess.CalledProcessError:
                    print(f"{Fore.RED}[!] Failed to install apktool. Please install manually.{Style.RESET_ALL}")
                    return False
            elif sys.platform == "win32":
                print(f"{Fore.RED}[!] Please install apktool manually on Windows.{Style.RESET_ALL}")
                print("    Download from: https://ibotpeaches.github.io/Apktool/install/")
                return False
            
            return False
    
    def decompile_apk(self):
        """Decompile the APK using apktool."""
        if not os.path.exists(self.apk_path):
            print(f"{Fore.RED}[!] APK file not found: {self.apk_path}{Style.RESET_ALL}")
            return False
        
        self.decompiled_dir = tempfile.mkdtemp(prefix="apk_analysis_")
        print(f"{Fore.BLUE}[*] Decompiling APK to:{Style.RESET_ALL} {self.decompiled_dir}")
        
        try:
            print(f"{Fore.BLUE}[*] Running apktool... (this may take a moment){Style.RESET_ALL}")
            subprocess.run(["apktool", "d", self.apk_path, "-o", self.decompiled_dir, "-f"], 
                           check=True, capture_output=True, text=True)
            print(f"{Fore.GREEN}[+] Decompilation successful{Style.RESET_ALL}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[!] Decompilation failed: {e.stderr}{Style.RESET_ALL}")
            return False
    
    def find_secrets_in_files(self):
        """Find potential secrets and API keys in all relevant files."""
        print(f"{Fore.BLUE}[*] Searching for secrets and API keys in all files...{Style.RESET_ALL}")
        
        # Regex patterns for common API key formats
        api_key_patterns = [
            (r'(?i)api[-_]?key\s*=\s*["\']([^"\']{8,})["\']', "API Key"),
            (r'(?i)secret[-_]?key\s*=\s*["\']([^"\']{8,})["\']', "Secret Key"),
            (r'(?i)app[-_]?key\s*=\s*["\']([^"\']{8,})["\']', "App Key"),
            (r'(?i)app[-_]?secret\s*=\s*["\']([^"\']{8,})["\']', "App Secret"),
            (r'(?i)auth[-_]?token\s*=\s*["\']([^"\']{8,})["\']', "Auth Token"),
            (r'(?i)oauth[-_]?token\s*=\s*["\']([^"\']{8,})["\']', "OAuth Token"),
            (r'(?i)access[-_]?token\s*=\s*["\']([^"\']{8,})["\']', "Access Token"),
            (r'(?i)client[-_]?secret\s*=\s*["\']([^"\']{8,})["\']', "Client Secret"),
            (r'(?i)client[-_]?id\s*=\s*["\']([^"\']{8,})["\']', "Client ID"),
            (r'(?i)password\s*=\s*["\']([^"\']{8,})["\']', "Password"),
            (r'(?i)firebase[-_]?key\s*=\s*["\']([^"\']{8,})["\']', "Firebase Key"),
            (r'(?i)bearer\s*=\s*["\']([^"\']{8,})["\']', "Bearer Token"),
            (r'(?i)jwt\s*=\s*["\']([^"\']{8,})["\']', "JWT"),
            (r'(?i)github[-_]?token\s*=\s*["\']([^"\']{8,})["\']', "GitHub Token"),
            (r'(?i)aws[-_]?key\s*=\s*["\']([^"\']{8,})["\']', "AWS Key"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
            (r'(?i)fb[a-z0-9_-]{30,}', "Facebook API Key"),
            (r'(?i)twitter[a-z0-9_-]{35,}', "Twitter API Key"),
            (r'[a-z0-9]{32}-us[0-9]{1,2}', "Mailchimp API Key"),
            (r'xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}', "Slack API Key"),
            (r'sk_live_[0-9a-zA-Z]{24}', "Stripe API Key"),
            (r'sq0atp-[0-9A-Za-z\-_]{22}', "Square Access Token"),
            (r'sq0csp-[0-9A-Za-z\-_]{43}', "Square OAuth Secret"),
            (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "PayPal Access Token"),
            (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "Amazon MWS Auth Token"),
            (r'(?i)basic [a-zA-Z0-9=:_\+\/-]{5,100}', "Basic Auth Credentials"),
            (r'(?i)bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}', "Bearer Token"),
            (r'(?i)AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'(?i)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "UUID/GUID")
        ]
        
        # Define file types to search
        file_extensions = [
            '.xml', '.json', '.properties', '.gradle', '.java', '.kt', '.smali', 
            '.txt', '.html', '.js', '.css', '.yml', '.yaml', '.config', '.ini',
            '.cfg', '.conf'
        ]
        
        total_files = 0
        scanned_files = 0
        
        # Count total files first to show progress
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    total_files += 1
        
        # Now scan the files
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.decompiled_dir)
                    
                    scanned_files += 1
                    if scanned_files % 50 == 0:
                        print(f"{Fore.BLUE}[*] Scanning file {scanned_files}/{total_files} ({int(scanned_files/total_files*100)}%){Style.RESET_ALL}")
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern, key_type in api_key_patterns:
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    try:
                                        # If the pattern has a capturing group, use it
                                        if len(match.groups()) > 0:
                                            key_value = match.group(1)
                                        # Otherwise use the whole match
                                        else:
                                            key_value = match.group(0)
                                        
                                        # Exclude some common false positives
                                        if key_value.lower() in ['true', 'false', 'null', 'undefined', 'example', 'password', 'username']:
                                            continue
                                            
                                        # Get some context around the match
                                        start = max(0, match.start() - 20)
                                        end = min(len(content), match.end() + 20)
                                        context = content[start:end].replace('\n', ' ').strip()
                                        
                                        self.findings["api_keys"].append({
                                            "file": rel_path,
                                            "key_type": key_type,
                                            "value": key_value,
                                            "context": context,
                                            "line": content[:match.start()].count('\n') + 1
                                        })
                                    except Exception as e:
                                        print(f"{Fore.RED}[!] Error processing match in {rel_path}: {e}{Style.RESET_ALL}")
                    except Exception as e:
                        # Just skip files we can't read
                        pass
        
        if self.findings["api_keys"]:
            print(f"{Fore.YELLOW}[!] Found {len(self.findings['api_keys'])} potential API keys/secrets{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No API keys/secrets found{Style.RESET_ALL}")
    
    def analyze_manifest_for_exported_components(self):
        """Find exported activities in AndroidManifest.xml."""
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            print(f"{Fore.RED}[!] AndroidManifest.xml not found at {manifest_path}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Analyzing AndroidManifest.xml for exported components...{Style.RESET_ALL}")
        
        try:
            # Parse the XML
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Define the Android namespace
            android_ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            # Find all components
            components = {
                "activity": root.findall('.//activity', namespaces=android_ns),
                "receiver": root.findall('.//receiver', namespaces=android_ns),
                "service": root.findall('.//service', namespaces=android_ns),
                "provider": root.findall('.//provider', namespaces=android_ns)
            }
            
            for component_type, component_list in components.items():
                for component in component_list:
                    # Check if exported attribute exists and is true
                    exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                    
                    # Get the component name
                    name = component.get('{http://schemas.android.com/apk/res/android}name')
                    
                    # Check if there are intent filters (implicitly exported if API level < 31)
                    has_intent_filter = component.find('.//intent-filter', namespaces=android_ns) is not None
                    
                    # Component is exported if: 
                    # 1. Explicitly exported=true
                    # 2. Has intent-filter and no exported attribute (implicit export for API < 31)
                    if (exported == "true") or (has_intent_filter and exported is None):
                        permission = component.get('{http://schemas.android.com/apk/res/android}permission')
                        
                        # For intent filters, get the actions
                        intent_actions = []
                        if has_intent_filter:
                            intent_filters = component.findall('.//intent-filter', namespaces=android_ns)
                            for intent_filter in intent_filters:
                                actions = intent_filter.findall('.//action', namespaces=android_ns)
                                for action in actions:
                                    action_name = action.get('{http://schemas.android.com/apk/res/android}name')
                                    if action_name:
                                        intent_actions.append(action_name)
                        
                        self.findings["exported_activities"].append({
                            "type": component_type,
                            "name": name or "unknown",
                            "has_permission": permission is not None,
                            "permission": permission,
                            "explicitly_exported": exported == "true",
                            "has_intent_filter": has_intent_filter,
                            "intent_actions": intent_actions
                        })
            
            if self.findings["exported_activities"]:
                print(f"{Fore.YELLOW}[!] Found {len(self.findings['exported_activities'])} exported components{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No exported components found{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing AndroidManifest.xml: {e}{Style.RESET_ALL}")
    
    def check_webview_vulnerabilities(self):
        """Check for common WebView vulnerabilities."""
        print(f"{Fore.BLUE}[*] Checking for WebView vulnerabilities...{Style.RESET_ALL}")
        
        webview_patterns = [
            (r'setJavaScriptEnabled\s*\(\s*true\s*\)', "JavaScript enabled in WebView", "HIGH"),
            (r'setAllowFileAccess\s*\(\s*true\s*\)', "File access enabled in WebView", "MEDIUM"),
            (r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)', "File URL access enabled in WebView", "HIGH"),
            (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', "Universal access from file URLs enabled", "HIGH"),
            (r'setDomStorageEnabled\s*\(\s*true\s*\)', "DOM storage enabled in WebView", "LOW"),
            (r'setDatabaseEnabled\s*\(\s*true\s*\)', "Database enabled in WebView", "LOW"),
            (r'addJavascriptInterface\s*\(', "JavaScript interface added to WebView", "MEDIUM"),
            (r'loadUrl\s*\(\s*[\'"][^\'"](file:|content:|data:)[^\'"\)][\'"]\s*\)', "Loading potentially unsafe content in WebView", "MEDIUM"),
            (r'loadData\s*\(', "Loading data in WebView", "LOW"),
            (r'onReceivedSslError[^{]\{[^}]*proceed\s\(', "SSL errors ignored in WebView", "HIGH")
        ]
        
        # Recursively search all Java and Kotlin files
        for ext in ['.java', '.kt', '.smali']:
            for root, dirs, files in os.walk(self.decompiled_dir):
                for file in files:
                    if file.endswith(ext):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                # First check if the file uses WebView at all
                                if re.search(r'WebView|webview', content, re.IGNORECASE):
                                    for pattern, description, severity in webview_patterns:
                                        matches = re.finditer(pattern, content)
                                        for match in matches:
                                            rel_path = os.path.relpath(file_path, self.decompiled_dir)
                                            line_number = content[:match.start()].count('\n') + 1
                                            
                                            # Get some context around the match
                                            start = max(0, match.start() - 20)
                                            end = min(len(content), match.end() + 20)
                                            context = content[start:end].replace('\n', ' ').strip()
                                            
                                            self.findings["webview_issues"].append({
                                                "file": rel_path,
                                                "line": line_number,
                                                "issue": description,
                                                "severity": severity,
                                                "code": match.group(0),
                                                "context": context
                                            })
                        except Exception as e:
                            # Just skip files we can't read
                            pass
        
        if self.findings["webview_issues"]:
            print(f"{Fore.YELLOW}[!] Found {len(self.findings['webview_issues'])} WebView security issues{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No WebView security issues found{Style.RESET_ALL}")
    
    def check_other_vulnerabilities(self):
        """Check for other common Android security issues."""
        print(f"{Fore.BLUE}[*] Checking for other common vulnerabilities...{Style.RESET_ALL}")
        
        vulnerability_patterns = [
            (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', "Insecure file permissions", "HIGH"),
            (r'getExternalStorage', "Using external storage without proper checks", "MEDIUM"),
            (r'setAllowAllSocketRequests\s*\(\s*true\s*\)', "Allowing all socket requests", "MEDIUM"),
            (r':\s*Base64\.encod', "Potentially using Base64 as encryption", "MEDIUM"),
            (r'SQLException|execSQL', "SQL usage - check for SQL injection", "MEDIUM"),
            (r'PackageManager\.GET_SIGNATURES', "App is checking signatures - possible security bypass", "LOW"),
            (r'Runtime\.exec|ProcessBuilder', "Command execution - potential RCE", "HIGH"),
            (r'interface\s+DeepLinkHandler|DeepLinkActivity', "Deep link handling - check for validation", "MEDIUM"),
            (r'IntentFilter.*android\.intent\.action\.VIEW', "URL handling - check for validation", "MEDIUM"),
            (r'\"https://|\"http://', "Hardcoded URLs - check for HTTP usage", "LOW"),
            (r'SecureRandom\.setSeed', "Setting a static seed for SecureRandom", "HIGH"),
            (r'TrustManager\s+[^{]+\{[^}]return null;[^}]\}', "Insecure TrustManager implementation", "HIGH"),
            (r'HostnameVerifier\s+[^{]+\{[^}]return true;[^}]\}', "Insecure HostnameVerifier implementation", "HIGH"),
            (r'getWritableDatabase|openDatabase|getReadableDatabase', "Database access - check for encryption", "LOW")
        ]
        
        # Recursively search all Java, Kotlin, and Smali files
        for ext in ['.java', '.kt', '.smali']:
            for root, dirs, files in os.walk(self.decompiled_dir):
                for file in files:
                    if file.endswith(ext):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern, description, severity in vulnerability_patterns:
                                    matches = re.finditer(pattern, content)
                                    for match in matches:
                                        rel_path = os.path.relpath(file_path, self.decompiled_dir)
                                        line_number = content[:match.start()].count('\n') + 1
                                        
                                        # Get some context around the match
                                        start = max(0, match.start() - 20)
                                        end = min(len(content), match.end() + 20)
                                        context = content[start:end].replace('\n', ' ').strip()
                                        
                                        self.findings["other_issues"].append({
                                            "file": rel_path,
                                            "line": line_number,
                                            "issue": description,
                                            "severity": severity,
                                            "code": match.group(0),
                                            "context": context
                                        })
                        except Exception as e:
                            # Just skip files we can't read
                            pass
        
        # Also check the manifest for common security issues
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for backup enabled
                    if re.search(r'android:allowBackup="true"', content):
                        self.findings["other_issues"].append({
                            "file": "AndroidManifest.xml",
                            "line": 0,
                            "issue": "Backup enabled",
                            "severity": "MEDIUM",
                            "code": "android:allowBackup=\"true\"",
                            "context": "Application data can be backed up and potentially accessed by other apps"
                        })
                    
                    # Check for debuggable flag
                    if re.search(r'android:debuggable="true"', content):
                        self.findings["other_issues"].append({
                            "file": "AndroidManifest.xml",
                            "line": 0,
                            "issue": "App is debuggable",
                            "severity": "HIGH",
                            "code": "android:debuggable=\"true\"",
                            "context": "Debuggable apps expose sensitive information and can be easily reverse engineered"
                        })
                    
                    # Check for testOnly flag
                    if re.search(r'android:testOnly="true"', content):
                        self.findings["other_issues"].append({
                            "file": "AndroidManifest.xml",
                            "line": 0,
                            "issue": "App is testOnly",
                            "severity": "MEDIUM",
                            "code": "android:testOnly=\"true\"",
                            "context": "The app is only intended for testing, not for production use"
                        })
                    
                    # Check for insecure permissions
                    sensitive_permissions = [
                        "INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
                        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_CONTACTS",
                        "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG", "CAMERA",
                        "RECORD_AUDIO", "READ_PHONE_STATE"
                    ]
                    
                    for perm in sensitive_permissions:
                        if re.search(f'uses-permission.*?{perm}', content):
                            severity = "HIGH" if perm in ["READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION"] else "MEDIUM"
                            self.findings["other_issues"].append({
                                "file": "AndroidManifest.xml",
                                "line": 0,
                                "issue": f"Uses sensitive permission: {perm}",
                                "severity": severity,
                                "code": f"uses-permission android:name=\"android.permission.{perm}\"",
                                "context": f"App requests {perm} permission which may expose sensitive user data if misused"
                            })
            except Exception as e:
                print(f"{Fore.RED}[!] Error checking manifest for other vulnerabilities: {e}{Style.RESET_ALL}")
        
        if self.findings["other_issues"]:
            print(f"{Fore.YELLOW}[!] Found {len(self.findings['other_issues'])} other potential security issues{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No other security issues found{Style.RESET_ALL}")
    
    def print_findings(self):
        """Print all findings in a structured format with colors."""
        # Calculate risk score
        risk_score = self.calculate_risk_score()
        
        # Define colors for severity levels
        severity_colors = {
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.BLUE
        }
        
        # Print the report header
        print("\n" + "="*80)
        print(f"{Fore.CYAN}APK SECURITY ANALYSIS RESULTS{Style.RESET_ALL}")
        print("="*80)
        
        # Print risk score
        risk_color = Fore.GREEN
        if risk_score > 30:
            risk_color = Fore.RED
        elif risk_score > 15:
            risk_color = Fore.YELLOW
            
        print(f"\n{Fore.WHITE}Overall Risk Score: {risk_color}{risk_score}/100{Style.RESET_ALL}")
        print(f"Risk Level: {risk_color}{self.get_risk_level(risk_score)}{Style.RESET_ALL}")
        
        # Print scan summary
        print("\n" + "-"*80)
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print("-"*80)
        total_issues = sum(len(issues) for issues in self.findings.values())
        print(f"  APK File: {self.app_name}")
        print(f"  Scan Date: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Total Issues Found: {total_issues}")
        # Count issues by severity
        high_issues = medium_issues = low_issues = 0
        for category in self.findings.values():
            for issue in category:
                if "severity" in issue:
                    if issue["severity"] == "HIGH":
                        high_issues += 1
                    elif issue["severity"] == "MEDIUM":
                        medium_issues += 1
                    else:
                        low_issues += 1
        
        print(f"  {Fore.RED}High Severity Issues: {high_issues}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Medium Severity Issues: {medium_issues}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Low Severity Issues: {low_issues}{Style.RESET_ALL}")
        
        # Detailed findings by category
        if self.findings["api_keys"]:
            print("\n" + "-"*80)
            print(f"{Fore.CYAN}POTENTIAL SECRETS/API KEYS FOUND{Style.RESET_ALL}")
            print("-"*80)
            for idx, key in enumerate(self.findings["api_keys"], 1):
                print(f"{Fore.YELLOW}[{idx}] {key['key_type']} found in:{Style.RESET_ALL}")
                print(f"  File: {key['file']}:{key['line']}")
                print(f"  Value: {Fore.RED}{key['value']}{Style.RESET_ALL}")
                print(f"  Context: {Fore.WHITE}{key['context']}{Style.RESET_ALL}\n")

        if self.findings["exported_activities"]:
            print("\n" + "-"*80)
            print(f"{Fore.CYAN}EXPORTED COMPONENTS FOUND{Style.RESET_ALL}")
            print("-"*80)
            for idx, comp in enumerate(self.findings["exported_activities"], 1):
                print(f"{Fore.YELLOW}[{idx}] {comp['type'].upper()} {comp['name']}{Style.RESET_ALL}")
                print(f"  Explicitly exported: {comp['explicitly_exported']}")
                print(f"  Has intent filter: {comp['has_intent_filter']}")
                if comp['intent_actions']:
                    print(f"  Intent actions: {', '.join(comp['intent_actions'])}")
                print(f"  Protected by permission: {comp['has_permission']}")
                if comp['permission']:
                    print(f"  Required permission: {comp['permission']}")
                print()

        if self.findings["webview_issues"]:
            print("\n" + "-"*80)
            print(f"{Fore.CYAN}WEBVIEW VULNERABILITIES FOUND{Style.RESET_ALL}")
            print("-"*80)
            for idx, issue in enumerate(self.findings["webview_issues"], 1):
                color = severity_colors.get(issue["severity"], Fore.WHITE)
                print(f"{color}[{idx}] [{issue['severity']}] {issue['issue']}{Style.RESET_ALL}")
                print(f"  File: {issue['file']}:{issue['line']}")
                print(f"  Code: {Fore.WHITE}{issue['code']}{Style.RESET_ALL}")
                print(f"  Context: {issue['context']}\n")

        if self.findings["other_issues"]:
            print("\n" + "-"*80)
            print(f"{Fore.CYAN}OTHER SECURITY ISSUES FOUND{Style.RESET_ALL}")
            print("-"*80)
            for idx, issue in enumerate(self.findings["other_issues"], 1):
                color = severity_colors.get(issue["severity"], Fore.WHITE)
                print(f"{color}[{idx}] [{issue['severity']}] {issue['issue']}{Style.RESET_ALL}")
                print(f"  File: {issue['file']}:{issue['line']}")
                print(f"  Code: {Fore.WHITE}{issue['code']}{Style.RESET_ALL}")
                print(f"  Context: {issue['context']}\n")

        print("\n" + "="*80)
        print(f"{Fore.CYAN}SCAN COMPLETE{Style.RESET_ALL}")
        print("="*80)
        
    def calculate_risk_score(self):
        """Calculate a risk score based on findings."""
        score = 0
        # API keys and secrets
        score += len(self.findings["api_keys"]) * 5
        # Exported components
        score += len(self.findings["exported_activities"]) * 3
        # WebView issues
        for issue in self.findings["webview_issues"]:
            if issue["severity"] == "HIGH":
                score += 10
            elif issue["severity"] == "MEDIUM":
                score += 5
            else:
                score += 2
        # Other issues
        for issue in self.findings["other_issues"]:
            if issue["severity"] == "HIGH":
                score += 8
            elif issue["severity"] == "MEDIUM":
                score += 4
            else:
                score += 1
        return min(score, 100)  # Cap at 100

    def get_risk_level(self, score):
        """Convert risk score to textual representation."""
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        else:
            return "Low"

    def save_report(self, filename):
        """Save findings to a report file."""
        report = {
            "metadata": {
                "app_name": self.app_name,
                "scan_time": self.scan_time.isoformat(),
                "risk_score": self.calculate_risk_score(),
                "risk_level": self.get_risk_level(self.calculate_risk_score())
            },
            "findings": self.findings
        }
        
        # Save JSON report
        with open(f"{filename}.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Save human-readable report
        with open(f"{filename}.txt", "w") as f:
            f.write(f"APK Security Analysis Report\n")
            f.write(f"============================\n\n")
            f.write(f"Application: {self.app_name}\n")
            f.write(f"Scan Date: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Risk Score: {report['metadata']['risk_score']} ({report['metadata']['risk_level']})\n\n")
            
            for category, items in self.findings.items():
                if items:
                    f.write(f"{category.replace('_', ' ').title()}:\n")
                    f.write("-"*50 + "\n")
                    for item in items:
                        f.write(f"• {json.dumps(item, indent=2)}\n\n")

        print(f"{Fore.GREEN}[+] Report saved to {filename}.json and {filename}.txt{Style.RESET_ALL}")

    def cleanup(self):
        """Clean up decompiled directory."""
        if self.decompiled_dir and os.path.exists(self.decompiled_dir):
            print(f"{Fore.BLUE}[*] Cleaning up decompiled files...{Style.RESET_ALL}")
            shutil.rmtree(self.decompiled_dir)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-apk>")
        sys.exit(1)
        
    apk_path = sys.argv[1]
    analyzer = APKAnalyzer(apk_path)
    analyzer.print_banner()
    
    if not analyzer.check_apktool_installed():
        sys.exit(1)
        
    if analyzer.decompile_apk():
        try:
            analyzer.analyze_manifest_for_exported_components()
            analyzer.find_secrets_in_files()
            analyzer.check_webview_vulnerabilities()
            analyzer.check_other_vulnerabilities()
            analyzer.print_findings()
            
            # Ask user if they want to save the report
            save_report = input("\nSave report to file? (Enter filename or press Enter to skip): ").strip()
            if save_report:
                if not save_report.endswith(".json"):
                    save_report += ".json"  # Ensure the file has a .json extension
                analyzer.save_report(save_report)
                
        finally:
            analyzer.cleanup()

if __name__ == "_main_":
    main()