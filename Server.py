'''
==================================================================================================================================
Project Name:
   EDR Server - Endpoint Detection and Response System

Developers:
   Ahmad Doulat
   Mohammad Rousan
   Ahmad Delaa

Description:
   This script is part of an Endpoint Detection and Response (EDR) system.
   It acts as the server component, handling client connections, monitoring
   for potential threats, and logging activities in real-time.

==================================================================================================================================
'''
import socket
import urllib.request
from pathlib import Path
from subprocess import check_output, run
from threading import Thread
from time import sleep

TAB_1 = '\t'
TAB_2 = '\t\t'

PROJECTPATH = Path(__file__).resolve().parent
HOST = '192.168.1.153'  # Server IP
PORT = 1111  # Server port

# Socket object
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connectionsCount = 0  # Number of connected clients
activeAddressesList = []  # List of connected addresses
openClientSocketsList = []  # List of open socket connections

def apache2Start():
    """Start Apache2 server and ensure restricted_sites.html is accessible."""
    try:
        apache2InstallStatus = check_output(
            "dpkg --get-selections | grep apache2-bin | awk '{print $2}'", shell=True)
        if apache2InstallStatus:
            run("service apache2 start", shell=True)
            try:
                response = urllib.request.urlopen(f'http://{HOST}/restricted_sites.html')
                if response.status != 200:
                    run('service apache2 restart', shell=True)
                    sleep(5)
            except urllib.error.HTTPError as e:
                print(f"[ERROR] HTTP Error {e.code}: {e.reason}")
                run('service apache2 restart', shell=True)
                print("[INFO] Restarting Apache2 service. Ensure restricted_sites.html exists in /var/www/html.")
            except Exception as e:
                print(f"[ERROR] Unexpected error: {e}")
        else:
            exit('[ERROR] Apache2 service is not installed. Please install Apache2 and run the server again.')
    except Exception as e:
        exit(f'[ERROR] Failed to start Apache2 service: {e}')

    print('[INFO] Apache2 Server Started (http://localhost:80)')
    print('[INFO] restricted_sites.html copied to /var/www/html.\nEdit the file inside /var/www/html to add or remove restricted sites for clients.')

def handleClient(conn, connName):
    """Handle client connections and process incoming data."""
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data:
                break

            # Process the received data
            if "restricted" in data:
                timestamp = check_output("date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                log_entry = f"[{timestamp}]{TAB_1}\n_{connName}:\n+{data}"
                print(f'[INFO] Restricted site accessed by {connName}.')
            elif "DoS" in data:
                timestamp = check_output("date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                log_entry = f"[{timestamp}]{TAB_1}\n_{connName}:\n+{data}"
                print(f'[INFO] Potential DoS attack detected from {connName}.')

            # Broadcast the log entry to all connected clients (Log Viewers)
            for client in openClientSocketsList:
                try:
                    client.send(log_entry.encode())
                except:
                    print(f'[INFO] Client {connName} disconnected.')
                    openClientSocketsList.remove(client)
                    activeAddressesList.remove(connName)
                    global connectionsCount
                    connectionsCount -= 1

        except Exception as e:
            print(f"[ERROR] Error handling client {connName}: {e}")
            break

    conn.close()
    openClientSocketsList.remove(conn)
    activeAddressesList.remove(connName)
    connectionsCount -= 1
    print(f'[INFO] Client {connName} disconnected. Active connections: {connectionsCount}')

def checkConnections():
    """Check active client connections."""
    while True:
        global connectionsCount
        if len(openClientSocketsList) != 0:
            for x, currentSocket in enumerate(openClientSocketsList):
                try:
                    currentSocket.send(' '.encode())  # Ping the client to check connection
                except:
                    print(f'[INFO] Client {x} Disconnected!')
                    del openClientSocketsList[x], activeAddressesList[x]
                    connectionsCount -= 1
                    print(f'[INFO] Number of Active Connections: {connectionsCount}')
                    if connectionsCount > 0:
                        print('[INFO] Active addresses connected:')
                        for index, value in enumerate(activeAddressesList):
                            print(f'{TAB_1}{index}.{TAB_1}{value}')
        sleep(30)

def main():
    """Main server function to handle client connections."""
    try:
        serverSocket.bind((HOST, PORT))  # Bind the socket
        print(f'[INFO] Server address bound to self ({HOST})')
    except socket.error as error:
        exit(f'[ERROR] Error in Binding the Server:\n\033[31m{error}\033[0m')

    print(f'[INFO] Listening on port {PORT}... (Waiting for connections)')
    serverSocket.listen(50)

    # Close any previous connections if the server restarts
    for clientSocket in openClientSocketsList:
        clientSocket.close()
    del openClientSocketsList[:], activeAddressesList[:]

    while True:
        try:
            conn, (address, port) = serverSocket.accept()
            openClientSocketsList.append(conn)
            connName = f'{address}:{port}'
            print(f'[INFO] {connName} Connected!')

            welcomeMessage = f'Successfully connected to EDR Server at {HOST}:{PORT}'
            conn.send(welcomeMessage.encode())

            global connectionsCount
            connectionsCount += 1
            activeAddressesList.append(connName)

            print(f'[INFO] Number of Active Connections: {connectionsCount}')

            Thread(target=handleClient, args=(conn, connName)).start()
            Thread(target=checkConnections).start()
        except socket.error as acceptError:
            print(f'[ERROR] Accepting Connection:\n\033[31m{acceptError}\033[0m')
            continue

if __name__ == '__main__':
    apache2Start()
    main()
