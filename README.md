# EDR Server - Endpoint Detection and Response System

## Overview
The **EDR Server** is a Python-based Endpoint Detection and Response (EDR) system designed to monitor and detect potential security threats in real-time. It consists of three main components:
1. **Server**: Handles client connections, logs activities, and detects threats.
2. **Client**: Monitors the system for suspicious activities and sends alerts to the server.
3. **Log Viewer**: Displays real-time logs and alerts in a user-friendly interface.

This project is developed as part of a Cyber Security course and is designed to provide a basic yet functional EDR system for educational purposes.

---

## Features

### Server Features
1. **Real-Time Logging**:
   - Captures and logs activities from connected clients in real-time.
   - Logs include timestamps, client IP addresses, and event details.

2. **Threat Detection**:
   - Detects restricted website access.
   - Identifies potential DoS (Denial of Service) attacks.
   - Monitors for ransomware activity.
   - Detects phishing attempts.
   - Alerts for privilege escalation attempts.
   - Detects fileless malware.

3. **Apache2 Integration**:
   - Hosts a restricted sites list on an Apache2 server.
   - Dynamically updates the list of restricted websites.

4. **Client Management**:
   - Manages multiple client connections.
   - Tracks active clients and handles disconnections gracefully.

5. **Threaded Architecture**:
   - Uses multi-threading to handle multiple clients simultaneously.
   - Ensures efficient resource utilization.

---

### Client Features
1. **DNS Monitoring**:
   - Sniffs DNS queries to detect access to restricted websites.
   - Sends alerts to the server when restricted sites are accessed.

2. **DoS Attack Detection**:
   - Monitors network traffic for SYN flood attacks.
   - Calculates packet rates and identifies potential DoS attacks.

3. **Ransomware Detection**:
   - Monitors files in a specified directory for changes.
   - Detects ransomware activity by comparing file hashes.

4. **Phishing Detection**:
   - Sniffs HTTP traffic for suspicious URLs.
   - Alerts the server when phishing attempts are detected.

5. **Privilege Escalation Monitoring**:
   - Monitors system logs for unauthorized privilege escalation attempts.
   - Uses PowerShell (Windows) or `grep` (Linux) to detect suspicious activity.

6. **Fileless Malware Detection**:
   - Monitors running processes for suspicious behavior.
   - Detects fileless malware by analyzing process command lines.

---

### Log Viewer Features
1. **Real-Time Log Display**:
   - Displays logs in a table format with columns for sequence number, event type, timestamp, IP address, and message.

2. **Filtering and Sorting**:
   - Allows filtering logs by event type (e.g., restricted access, DoS attack).
   - Supports sorting by timestamp or sequence number.

3. **Clear Logs**:
   - Provides a button to clear all logs from the table.

4. **Status Updates**:
   - Displays the current status of the server (e.g., "Connected to server", "Capture stopped").

5. **User-Friendly Interface**:
   - Built using Tkinter for a clean and intuitive interface.
   - Supports dark mode for better readability.

---

## Requirements

### Server Side:
1. **Operating System**: Linux (e.g., Ubuntu).
2. **Privileges**: Root access is required to start/stop services and access system logs.
3. **Python Version**: Python 3+.
4. **Dependencies**:
   - `socket`
   - `urllib.request`
   - `subprocess`
   - `threading`
   - `datetime`

### Client Side:
1. **Operating System**: Windows or Linux.
2. **Network**: Must be connected to the same local network as the server.
3. **Python Version**: Python 3+.
4. **Dependencies**:
   - `scapy`
   - `beautifulsoup4`
   - `lxml`
   - `psutil`

---

## Installation

### Server Setup
1. **Install Apache2**:
   ```bash
   sudo apt update
   sudo apt install apache2
