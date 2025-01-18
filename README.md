# EDR Client - Endpoint Detection and Response System

## Overview
The **EDR Client** is a Python-based component of an Endpoint Detection and Response (EDR) system. It is designed to monitor and detect potential security threats on the client machine and send alerts to the **EDR Server** in real-time. This client script is part of a larger EDR system that includes a server and a log viewer.

---

## Features

### 1. **Restricted Website Detection**
   - Monitors DNS queries to detect access to restricted websites.
   - Fetches the list of restricted sites from the server's Apache2-hosted `restricted_sites.html` page.
   - Sends an alert to the server when a restricted site is accessed.

### 2. **DoS Attack Detection**
   - Monitors network traffic for SYN flood attacks.
   - Calculates the rate of SYN packets to detect potential DoS attacks.
   - Sends an alert to the server when a DoS attack is detected.

### 3. **Dynamic Threshold Calculation**
   - Uses a dynamic threshold to detect sustained DoS attacks.
   - Adjusts the threshold based on the average packet rate over the last 10 seconds.

### 4. **Multi-Threaded Architecture**
   - Runs multiple monitoring tasks concurrently using threads:
     - Restricted site monitoring.
     - DoS attack detection.
   - Ensures efficient resource utilization.

### 5. **Cross-Platform Support**
   - Works on both **Windows** and **Linux** operating systems.
   - Automatically adapts to the running OS for file handling and system commands.

### 6. **Graceful Termination**
   - Handles termination signals (e.g., `Ctrl+C`) gracefully.
   - Closes the socket connection and terminates all threads before exiting.

---

## Requirements

### 1. **Operating System**
   - Windows or Linux.

### 2. **Python Version**
   - Python 3+.

### 3. **Dependencies**
   - `scapy`: For packet sniffing and network analysis.
   - `beautifulsoup4`: For parsing the restricted sites list from the server.
   - `lxml`: A dependency for BeautifulSoup to parse HTML efficiently.
   - `psutil`: For system monitoring (optional, if additional features are added).

   Install dependencies using:
   ```bash
   pip install scapy beautifulsoup4 lxml psutil
