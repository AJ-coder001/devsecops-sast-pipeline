import os
import re
import sys
from colorama import Fore, Style, init

# Initialize colorama for terminal output
init(autoreset=True)

# Define SecuritY rules (Regex patterns)
RULES = {
    "Hardcoded AWS Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Generic Password Assignment": r"(password|passwd|secret|api_key|token)\s*=\s*['\"][A-Za-z0-9_\-]{4,}['\"],",
    "SQL Injection Risk": r"execute\s*\(\s*['\"].*%\s*.*['\"]\s*\)",
    "Command Injection Risk (os.system)": r"os\.system\s*\("
}

def scan_file(file_path):
    vulnerabilities = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for rule_name, pattern in RULES.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        # Avoid flagging the scanner file itself
                        if "scanner.py" in file_path and rule_name in line:
                            continue
                        vulnerabilities.append({
                            "file": file_path,
                            "line": line_number,
                            "issue": rule_name,
                            "snippet": line.strip()
                        })
    except Exception as e:
        pass
    return vulnerabilities
def main():
    print(f"{Fore.CYAN}================================================================")
    print(f"{Fore.CYAN}============Starting Security Scanner ==========================")
    print(f"{Fore.CYAN}================================================================\n")

    all_vulns = []
    # exclude system and hidden git files
    exclude_dirs = {'.git', '.devcontainer', '__pycache__'}

    for root, _, files in os.walk('.'):
        if any(excluded in root for excluded in exclude_dirs):
            continue
        for file in files:
            # Target common code and config files
            if file.endswith(('.py', '.js', '.txt', '.env', '.json', '.yml', 'Dockerfile')):
                file_path = os.path.join(root, file)
                vulns = scan_file(file_path)
                all_vulns.extend(vulns)

    # Output Results
    if all_vulns:
        print(f"{Fore.RED} CRITICAL SECURITY ISSUES FOUND:\n")
        for vuln in all_vulns:
            print(f"{Fore.YELLOW}Issue: {vuln['issue']}")
            print(f"  file: {vuln['file']} (Line {vuln['line']})")
            print(f"  Code: {Fore.WHITE}{vuln['snippet']}\n")
        print(f"{Fore.RED}Scan Failed. Fix Security Issues\n")
        sys.exit(1)  # Fail the build pipeline
    else:
        print(f"{Fore.GREEN} SUCCESS: No critical security issues found!")
        sys.exit(0)  # Pass the build pipeline


if __name__ == "__main__":
    main()
