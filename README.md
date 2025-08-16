
Automated Log Analyzer for Intrusion Detection
# Auth Log Analyzer 🛡️

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A Python-based tool designed to automate the analysis of Linux authentication logs (`auth.log`). This script parses log files to detect common security threats like brute-force attacks, identifies successful logins, and flags critical correlations between the two, saving the findings into timestamped reports.

---

## ## Key Features

* **🕵️ Brute-Force Detection:** Automatically identifies and counts failed login attempts from unique IP addresses.
* **✅ Successful Login Identification:** Parses the log for all successful authentication events.
* **🚨 Critical Alert Correlation:** Flags high-priority threats by identifying IPs that were involved in brute-force attempts and also had a successful login.
* **📄 Automated Reporting:** On every run, the script automatically saves a detailed, timestamped report to a designated `reports/` directory for a complete audit trail.

---

## ## Demo

Here is a sample of the script's output after running an analysis.

```bash
$ python3 analyzer.py

[*] Starting analysis of auth.log...

[+] Brute-Force Attackers Detected:
========================================
1.2.3.4    4
Name: count, dtype: int64
========================================

[+] Successful Logins Detected:
========================================
  IP: 1.2.3.4, Users: ['<your-username>']
========================================

[!!!] CRITICAL ALERT: Suspicious IP with Successful Login Found!
=======================================================
  IP: 1.2.3.4 had 4 failed attempts and successfully logged in as ['<your-username>']!
=======================================================

[*] Report successfully saved to: reports/report_2025-08-17_01-15-30.txt