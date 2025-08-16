# analyzer.py (Version 3)

import pandas as pd
import re
from collections import defaultdict

def detect_brute_force(filepath):
    """Identifies and counts brute-force attempts from IP addresses."""
    ip_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    detection_keywords = ["failed password", "authentication failure", "invalid user"]
    failed_ips = []

    with open(filepath, 'r') as file:
        for line in file:
            if any(keyword in line.lower() for keyword in detection_keywords):
                match = re.search(ip_regex, line)
                if match:
                    failed_ips.append(match.group(0))
    
    if failed_ips:
        return pd.Series(failed_ips).value_counts()
    return pd.Series() # Return an empty Series if no IPs are found

def detect_successful_logins(filepath):
    """Finds all successful logins and returns a dictionary of {ip: [users]}."""
    ip_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    # Regex to find the user from a successful login line
    user_regex = r"for user (\w+)|for (\w+) from"
    
    success_keywords = ["accepted password", "session opened for user"]
    successful_logins = defaultdict(list) # A dictionary that allows multiple values per key

    with open(filepath, 'r') as file:
        for line in file:
            if any(keyword in line.lower() for keyword in success_keywords):
                ip_match = re.search(ip_regex, line)
                user_match = re.search(user_regex, line)
                
                if ip_match and user_match:
                    # user_match.groups() will contain ('username', None) or (None, 'username')
                    # We filter out the None and get the first actual username found.
                    user = next(filter(None, user_match.groups()), None)
                    if user:
                        successful_logins[ip_match.group(0)].append(user)
    
    return successful_logins

def main():
    """Main function to orchestrate the log analysis."""
    log_file = "auth.log"
    print(f"[*] Starting analysis of {log_file}...")

    # Step 1: Detect brute-force attacks
    brute_force_attackers = detect_brute_force(log_file)
    if not brute_force_attackers.empty:
        print("\n[+] Brute-Force Attackers Detected:")
        print("="*40)
        print(brute_force_attackers)
        print("="*40)
    else:
        print("\n[*] No brute-force activity detected.")

    # Step 2: Detect successful logins
    successful_logins = detect_successful_logins(log_file)
    if successful_logins:
        print("\n[+] Successful Logins Detected:")
        print("="*40)
        for ip, users in successful_logins.items():
            # set(users) removes duplicate usernames for cleaner output
            print(f"  IP: {ip}, Users: {list(set(users))}")
        print("="*40)
    else:
        print("\n[*] No successful logins detected.")

    # Step 3: Correlate the data to find critical threats 🚨
    if not brute_force_attackers.empty and successful_logins:
        print("\n[!!!] CRITICAL ALERT: Suspicious IP with Successful Login Found!")
        print("="*55)
        # .index gives us the IP addresses from the Series
        for ip in brute_force_attackers.index:
            if ip in successful_logins:
                users = list(set(successful_logins[ip]))
                attempts = brute_force_attackers[ip]
                print(f"  IP: {ip} had {attempts} failed attempts and successfully logged in as {users}!")
        print("="*55)

if __name__ == "__main__":
    main()