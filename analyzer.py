# analyzer.py (Version 5 - Automated Reporting)

import pandas as pd
import re
from collections import defaultdict
import os
from datetime import datetime

# --- Configuration ---
# The log file we want to analyze
LOG_FILE_PATH = "auth.log" 
# The folder where we will save our reports
REPORTS_DIR = "reports" 

def detect_brute_force(filepath):
    """Identifies and counts brute-force attempts from IP addresses."""
    # This function's code remains the same
    ip_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    detection_keywords = ["failed password", "authentication failure", "invalid user"]
    failed_ips = []

    try:
        with open(filepath, 'r') as file:
            for line in file:
                if any(keyword in line.lower() for keyword in detection_keywords):
                    match = re.search(ip_regex, line)
                    if match:
                        failed_ips.append(match.group(0))
    except FileNotFoundError:
        # Handle case where the log file doesn't exist
        print(f"[!] Error: Log file not found at {filepath}")
        return pd.Series()
    
    if failed_ips:
        return pd.Series(failed_ips).value_counts()
    return pd.Series()

def detect_successful_logins(filepath):
    """Finds all successful logins and returns a dictionary of {ip: [users]}."""
    # This function's code remains the same
    ip_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    user_regex = r"for user (\w+)|for (\w+) from"
    success_keywords = ["accepted password", "session opened for user"]
    successful_logins = defaultdict(list)
    
    try:
        with open(filepath, 'r') as file:
            for line in file:
                if any(keyword in line.lower() for keyword in success_keywords):
                    ip_match = re.search(ip_regex, line)
                    user_match = re.search(user_regex, line)
                    
                    if ip_match and user_match:
                        user = next(filter(None, user_match.groups()), None)
                        if user:
                            successful_logins[ip_match.group(0)].append(user)
    except FileNotFoundError:
        # The error is already handled in the other function, so we can pass here
        pass

    return successful_logins

def main():
    """Main function to orchestrate the log analysis and auto-save the report."""
    print(f"[*] Starting analysis of {LOG_FILE_PATH}...")
    report_lines = [f"Analysis Report for: {LOG_FILE_PATH}\n"]

    brute_force_attackers = detect_brute_force(LOG_FILE_PATH)
    successful_logins = detect_successful_logins(LOG_FILE_PATH)
    
    # --- The rest of the analysis logic is the same ---
    # ... (code for generating report_lines) ...
    if not brute_force_attackers.empty:
        report_lines.append("\n[+] Brute-Force Attackers Detected:")
        report_lines.append("="*40)
        report_lines.append(brute_force_attackers.to_string())
        report_lines.append("="*40)
    else:
        report_lines.append("\n[*] No brute-force activity detected.")

    if successful_logins:
        report_lines.append("\n[+] Successful Logins Detected:")
        report_lines.append("="*40)
        for ip, users in successful_logins.items():
            report_lines.append(f"  IP: {ip}, Users: {list(set(users))}")
        report_lines.append("="*40)
    else:
        report_lines.append("\n[*] No successful logins detected.")

    if not brute_force_attackers.empty and successful_logins:
        report_lines.append("\n[!!!] CRITICAL ALERT: Suspicious IP with Successful Login Found!")
        report_lines.append("="*55)
        for ip in brute_force_attackers.index:
            if ip in successful_logins:
                users = list(set(successful_logins[ip]))
                attempts = brute_force_attackers[ip]
                report_lines.append(f"  IP: {ip} had {attempts} failed attempts and successfully logged in as {users}!")
        report_lines.append("="*55)
    
    # --- NEW: Automated saving logic ---
    final_report = "\n".join(report_lines)
    print(final_report)

    # 1. Create the reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # 2. Generate a systematic filename with a timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"report_{timestamp}.txt"
    
    # 3. Construct the full path and save the file
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    with open(report_path, 'w') as report_file:
        report_file.write(final_report)
        
    print(f"\n[*] Report successfully saved to: {report_path}")

if __name__ == "__main__":
    main()