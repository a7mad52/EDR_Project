#!/usr/bin/python3
""" Description: This is the client's code. """
import socket
import urllib.request
from os import path, remove
from platform import system
from subprocess import check_output, run
from threading import Thread
from time import sleep, time
from bs4 import BeautifulSoup
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR  # Import DNS and DNSQR from scapy.layers.dns
import signal
import sys
from collections import defaultdict

TAB_1 = '\t'
TAB_2 = '\t\t'

# Gets the running OS as a variable:
runningOS = system()

HOST = '192.168.1.153'  # Server IP.
PORT = 1111  # Server's listening port.

restrictedSitesList = []

# Signal handler function for graceful termination
def signal_handler(sig, frame):
    print("\nTerminating the program gracefully...")
    # Close the socket connection and terminate threads if needed
    clientSocket.close()
    sys.exit(0)

# main:
# Creates a socket object.
# Connects to server and prints the welcome message.
def main():
    global clientSocket
    # Client's Socket Object:
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('Trying to connect to the server...')
    try:
        clientSocket.connect((HOST, PORT))  # Connects to the server's socket.
        print(f'[INFO] You are connected to: {HOST} in port: {PORT}.')
        welcomeMessage = clientSocket.recv(1024)  # Receives welcome message.
        print(welcomeMessage.decode())
    except socket.error as error:
        exit(f'[ERROR] Connecting to the server failed:\n\033[31m{error}\033[0m')

# restricted_Sites_List_Maker:
# Creates a list of website names that will be used as arguments for the DNS sniffer.
# The function gets the websites from the restricted_sites.html webpage running on the apache2 server.
# Only the server admin will have access to the HTML where the blacklist is stored.
# The update happens every sleep(x seconds) - modify to your liking.
def restricted_Sites_List_Maker():
    while True:
        try:
            # Restricted Websites webpage:
            restrictedWebsites = f"http://{HOST}/restricted_sites.html"

            HTMLrestrictedWebsites = urllib.request.urlopen(restrictedWebsites).read()

            if not HTMLrestrictedWebsites:
                raise Exception("Failed to retrieve valid HTML content from the server")

            soup = BeautifulSoup(HTMLrestrictedWebsites, features="html.parser")  # Changed to html.parser

            body = soup.body
            if body:
                textRestictedWebsites = body.get_text()  # Gets text.
            else:
                raise Exception("No body found in the HTML content")

            # Breaks into lines and remove leading and trailing space on each:
            lines = (line.strip() for line in textRestictedWebsites.splitlines())

            # Breaks multi-headlines into a line each:
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))

            # Drops blank lines. Final result:
            textRestictedWebsites = '\n'.join(chunk for chunk in chunks if chunk)

            # Creates / Overwrites the list of sites to a txt file from the HTML page.
            if runningOS == "Windows":
                if path.exists("Restricted_Sites.txt"):
                    remove("Restricted_Sites.txt")

                with open("Restricted_Sites.txt", "w") as restrictedSitesFile:
                    restrictedSitesFile.write(textRestictedWebsites)
                    # Makes the file hidden.
                    run("attrib +h Restricted_Sites.txt", shell=True)

                # Appends the site to the restrictedSitesList:
                with open("Restricted_Sites.txt", "r") as f:
                    restrictedSitesList.clear()
                    for siteLine in f.readlines():
                        restrictedSitesList.append(siteLine.strip())

            elif runningOS == "Linux":
                with open(".Restricted_Sites.txt", "w") as restrictedSitesFile:
                    restrictedSitesFile.write(textRestictedWebsites)

                # Appends the site to the restrictedSitesList
                with open(".Restricted_Sites.txt", "r") as f:
                    restrictedSitesList.clear()
                    for siteLine in f.readlines():
                        restrictedSitesList.append(siteLine.strip())
        except Exception as e:
            print(f"[ERROR] Failed to update restricted sites list: {e}")
        sleep(60)

# findDNS:
# Sniffs DNS queries of the client.
# Gets only the name of the website from the query. Setting it to the url variable.
# If the name of the site from the restrictedSitesList is found in the current sniffed url variable - sends an alert to the server.
def findDNS(pkt):
    try:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):  # Ensure the packet contains DNS query (DNSQR layer)
            # Extract the queried domain name (URL)
            url = pkt[DNSQR].qname.decode().strip('.')

            # Check if the URL is in the restrictedSitesList
            for site in restrictedSitesList:
                if site in url:
                    clientSocket.send(
                        f'[ALERT] Entered a restricted website:\n{site}\n\n'.encode())
    except Exception as e:
        print(f"[ERROR] DNS sniffing failed: {e}")

# detectDos:
# Detects potential DoS attacks by monitoring the number of incoming packets.
# If the packet rate exceeds a threshold, it sends an alert to the server.
def detectDos():
    packet_count = 0
    packet_rate_history = []
    threshold = 10000  # Initial threshold (adjust based on your network)
    source_ip_count = defaultdict(int)  # Track source IPs

    while True:
        try:
            start_time = time.time()  # Use time.time() to get the current time
            # Sniff packets for 1 second
            packets = sniff(timeout=1, prn=lambda x: None)
            packet_count = len(packets)

            # Track source IPs
            for packet in packets:
                if IP in packet:
                    source_ip_count[packet[IP].src] += 1

            # Calculate packet rate (packets per second)
            packet_rate = packet_count / (time.time() - start_time)  # Use time.time() here

            # Update packet rate history (last 10 seconds)
            packet_rate_history.append(packet_rate)
            if len(packet_rate_history) > 10:
                packet_rate_history.pop(0)

            # Calculate dynamic threshold (average of last 10 seconds + buffer)
            dynamic_threshold = sum(packet_rate_history) / len(packet_rate_history) * 1.5

            # If packet rate exceeds the dynamic threshold, send an alert
            if packet_rate > dynamic_threshold:
                # Identify top source IPs
                top_ips = sorted(source_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]
                top_ips_str = ", ".join([f"{ip}: {count}" for ip, count in top_ips])

                # Send alert to EDR server
                alert_message = (
                    f'[ALERT] Potential DoS attack detected!\n'
                    f'Packet rate: {packet_rate:.2f} packets/sec\n'
                    f'Top source IPs: {top_ips_str}\n\n'
                )
                clientSocket.send(alert_message.encode())

                # Reset counters
                source_ip_count.clear()
                packet_rate_history.clear()

        except Exception as e:
            print(f"[ERROR] DoS detection failed: {e}")
        sleep(1)
        
# Register signal handler for graceful termination
signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    main()
    Thread(target=restricted_Sites_List_Maker).start()
    Thread(target=lambda: sniff(prn=findDNS)).start()
    Thread(target=detectDos).start()
