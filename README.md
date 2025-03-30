
# 🔍 DroidSentinel - Android APK Static Vulnerability Scanner

![DroidSentinel Banner](https://img.shields.io/badge/DroidSentinel-Android%20Security%20Scanner-blue?style=for-the-badge) [![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com/)

DroidSentinel is a powerful, open-source static analysis tool that scans Android APK files for security vulnerabilities, hardcoded secrets, and potential privacy issues.

## ✨ Features

-   **API Key & Secret Detection**: Identifies hardcoded API keys, tokens, and credentials
-   **Exported Component Analysis**: Flags potentially vulnerable exported activities, services, and receivers
-   **WebView Vulnerability Detection**: Detects insecure WebView implementations
-   **Security Configuration Analysis**: Examines permissions and security settings
-   **Comprehensive Risk Scoring**: Generates a weighted risk score to prioritize issues
-   **Beautiful Reports**: Outputs easy-to-read console output with color-coded findings
-   **Exportable Results**: Save findings as JSON or text reports

## 🖼️ Screenshot

```
╔═══════════════════════════════════════════════════════════════╗
║ █▀▀▄ █▀▀█ █▀▀█ ▀█▀ █▀▀▄    █▀▀ █▀▀ █▀▀▄ ▀▀█▀▀ ▀█▀ █▀▀▄ █▀▀ █ ║
║ █  █ █▄▄▀ █  █  █  █  █    ▀▀█ █▀▀ █  █   █    █  █  █ █▀▀ █ ║
║ ▀▀▀  ▀ ▀▀ ▀▀▀▀ ▀▀▀ ▀▀▀     ▀▀▀ ▀▀▀ ▀  ▀   ▀   ▀▀▀ ▀  ▀ ▀▀▀ ▀▀▀▀ ║
╚═══════════════════════════════════════════════════════════════╝
           Android APK Static Vulnerability Scanner by CyberNinja

```
![Screenshot 1](https://raw.githubusercontent.com/ch3tanbug/DroidSentinel/refs/heads/main/images/Screenshot%202025-03-07%20at%2011.06.44%E2%80%AFAM.png)

![Screenshot 2](https://raw.githubusercontent.com/ch3tanbug/DroidSentinel/refs/heads/main/images/Screenshot%202025-03-07%20at%2011.08.03%E2%80%AFAM.png)

## 🚀 Installation

### Prerequisites

-   Python 3.6 or higher
-   apktool (automatically installed on Linux/macOS if missing)

### Option 1: Using pip

```bash
pip install droidsentinel

```

### Option 2: From source

```bash
git clone https://github.com/priyanshukumargupta12/DroidSentinel.git
cd DroidSentinel
pip install -r requirements.txt

```

## 💻 Usage

```bash
python droidsentinel.py path/to/your/app.apk

```

Or if installed via pip:

```bash
droidsentinel path/to/your/app.apk

```

## 🔍 What It Detects

### 1. API Keys & Secrets

-   API keys (Google, Facebook, Twitter, etc.)
-   Authentication tokens (Bearer, Basic, JWT)
-   Database credentials
-   Secret keys and passwords

### 2. Exported Components

-   Activities accessible from other apps
-   Services that can be started by third parties
-   Broadcast receivers exposed to the system
-   Content providers with public data

### 3. WebView Vulnerabilities

-   JavaScript enabled without proper protections
-   File access enabled in WebView
-   SSL error handling bypasses
-   JavaScript interfaces that could lead to JavaScript injection

### 4. Other Security Issues

-   Insecure file permissions
-   Improper SSL/TLS implementations
-   Insecure random number generation
-   Use of insecure cryptographic methods
-   Sensitive permissions usage

## 📊 Sample Output

```
APK SECURITY ANALYSIS RESULTS
================================================================================

Overall Risk Score: 42/100
Risk Level: Medium

--------------------------------------------------------------------------------
SCAN SUMMARY
--------------------------------------------------------------------------------
  APK File: example.apk
  Scan Date: 2025-03-07 14:30:22
  Total Issues Found: 12
  High Severity Issues: 3
  Medium Severity Issues: 5
  Low Severity Issues: 4

--------------------------------------------------------------------------------
POTENTIAL SECRETS/API KEYS FOUND
--------------------------------------------------------------------------------
[1] API Key found in:
  File: assets/config.json:15
  Value: AIzaSyD8XUgGg3zV7bo1GgL2k2nF9H7x8uKC4Rk
  Context: "apiKey": "AIzaSyD8XUgGg3zV7bo1GgL2k2nF9H7x8uKC4Rk", "authDomain": "example-app.firebaseapp.com"

```

## 📋 Risk Scoring

DroidSentinel intelligently assigns a **risk score (0-100)** based on multiple security factors, including:

🔍 **Key Risk Factors:**  
- 🔑 **Hardcoded Secrets**: Number and sensitivity of exposed credentials  
- 🔐 **Exported Components**: Insecure activities, services, receivers, and content providers  
- 🌐 **WebView Configuration**: Risky JavaScript interfaces or mixed-content issues  
- 🛑 **Security Vulnerabilities**: Presence of known misconfigurations and weaknesses  
- 📲 **App Permissions & Configurations**: Excessive or dangerous permissions  

### 🏆 Risk Score Breakdown  

| **Score Range** | **Risk Level**   | 🚨 Impact Level |
|---------------|----------------|---------------|
| **75 - 100**  | 🔥 **Critical** | **Severe security risks – Immediate action required** |
| **50 - 74**   | ⚠️ **High**     | **Major security concerns – Needs urgent review** |
| **25 - 49**   | ⚡ **Medium**    | **Potential risks – Should be addressed** |
| **0 - 24**    | ✅ **Low**      | **Minimal risk – Best practices still recommended** |

DroidSentinel helps you **prioritize security fixes** by providing a clear **risk assessment**—so you can **focus on what matters most!** 🚀  


## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1.  Fork the repository
2.  Create a new branch (`git checkout -b feature/amazing-feature`)
3.  Make your changes
4.  Commit your changes (`git commit -m 'Add some amazing feature'`)
5.  Push to the branch (`git push origin feature/amazing-feature`)
6.  Open a Pull Request



## 🙏 Acknowledgements

-   Thanks to the [apktool](https://ibotpeaches.github.io/Apktool/) project for enabling APK decompilation
-   Thanks to the mobile security community for defining best practices

## 🔮 Upcoming Features

We're constantly improving DroidSentinel! Here's what's planned for future releases:

1. **Native Library Analysis**: Detection of hardcoded secrets in native C/C++ `.so` files  
2. **React Native Support**: Enhanced analysis and listing of libraries used in React Native applications  
3. **Firebase Vulnerability Automation**: Streamlined detection and validation of common Firebase configuration issues  
4. **Deep Code Flow Analysis**: Improved tracking of data flow to identify complex vulnerabilities  
5. **Custom Rule Creation**: Ability to define and share custom scanning rules  

## ⚠️ Important Disclaimer

**No automated tool can guarantee complete security!** DroidSentinel is designed to assist security professionals by identifying common issues, but should never replace:

1. Thorough manual code review by experienced security engineers  
2. Dynamic analysis and penetration testing  
3. Proper security architecture design and implementation  

We strongly recommend using DroidSentinel as part of a comprehensive security program that includes manual decompilation and code review. The security landscape evolves constantly, and while we strive to keep this tool updated with the latest patterns, new vulnerability classes emerge regularly.  

This tool should be considered an aid to, not a replacement for, security expertise. The developers of DroidSentinel assume no liability for any security issues not detected by the tool or for misuse of the tool itself.  


This tool is intended for security research and vulnerability assessment purposes only. Always obtain proper authorization before scanning applications you don't own. The authors are not responsible for any misuse of this tool.

----------

Made with ❤️ by [CyberNinja](https://github.com/priyanshukumargupta12)
