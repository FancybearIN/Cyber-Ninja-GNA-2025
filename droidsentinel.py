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
    def __init__(self, apk_path):
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
{Fore.GREEN}           Android APK Static Vulnerability Scanner by Ch3tanbug{Style.RESET_ALL}
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
            
            if sys.platform == "win32":
                try:
                    # URLs for apktool files
                    apktool_jar_url = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar"
                    apktool_bat_url = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat"
                    
                    # Paths to save the files
                    tools_dir = os.path.join(os.getcwd(), "tools")
                    os.makedirs(tools_dir, exist_ok=True)
                    apktool_jar_path = os.path.join(tools_dir, "apktool.jar")
                    apktool_bat_path = os.path.join(tools_dir, "apktool.bat")
                    
                    # Download apktool.jar
                    print(f"{Fore.BLUE}[*] Downloading apktool.jar...{Style.RESET_ALL}")
                    self.download_file(apktool_jar_url, apktool_jar_path)
                    
                    # Download apktool.bat
                    print(f"{Fore.BLUE}[*] Downloading apktool.bat...{Style.RESET_ALL}")
                    self.download_file(apktool_bat_url, apktool_bat_path)
                    
                    # Add tools directory to PATH
                    os.environ["PATH"] += os.pathsep + tools_dir
                    print(f"{Fore.GREEN}[+] apktool installed successfully!{Style.RESET_ALL}")
                    return True
                except Exception as e:
                    print(f"{Fore.RED}[!] Failed to install apktool: {e}{Style.RESET_ALL}")
                    return False
            else:
                print(f"{Fore.RED}[!] Please install apktool manually on your platform.{Style.RESET_ALL}")
                return False

    def download_file(self, url, dest_path):
        """Download a file from a URL to a destination path."""
        import requests
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"{Fore.GREEN}[+] Downloaded: {dest_path}{Style.RESET_ALL}")
        else:
            raise Exception(f"Failed to download {url}. HTTP Status Code: {response.status_code}")

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

    def find_secrets_in_files(self):
        """Find potential secrets and API keys in all relevant files."""
        print(f"{Fore.BLUE}[*] Searching for secrets and API keys in all files...{Style.RESET_ALL}")
        # Implementation remains unchanged...

    def check_webview_vulnerabilities(self):
        """Check for common WebView vulnerabilities."""
        print(f"{Fore.BLUE}[*] Checking for WebView vulnerabilities...{Style.RESET_ALL}")
        # Implementation remains unchanged...

    def check_other_vulnerabilities(self):
        """Check for other common Android security issues."""
        print(f"{Fore.BLUE}[*] Checking for other common vulnerabilities...{Style.RESET_ALL}")
        # Implementation remains unchanged...

    def print_findings(self):
        """Print all findings in a structured format with colors."""
        # Implementation remains unchanged...

    def save_report(self, filename):
        """Save findings to a report file."""
        # Implementation remains unchanged...

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
                analyzer.save_report(save_report)
                
        finally:
            analyzer.cleanup()

if __name__ == "__main__":
    main()