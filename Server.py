#!/usr/bin/python3
'''
==================================================================================================================================
Course:
   Cyber Security, May, 2020
Project Name:
   #3 - Python - Endpoint Detection and Response.
Objective:
   Create an Endpoint Detection and Response System (EDR)
Student Name:
   Robert Jonny Tiger.
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
HOST = '192.168.1.153'
PORT = 1111

# Socket object.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connectionsCount = 0  # How many clients are connected to the server.
activeAddressesList = []  # List of connected addresses.
openClientSocketsList = []  # List of open socket connections.

# apache2Start:
# Checks if apache2 is installed. If not, exits the code with a message.
# Starts apache2 server.
# Copies the local restricted_sites.html to the actual html folder in /var/www/html where apache2 is running from.
# Server admin edits the file inside the /var/www/html to update the restricted sites list.
def apache2Start():
    try:
        apache2InstallStatus = check_output(
            "dpkg --get-selections | grep apache2-bin | awk '{print $2}'", shell=True)
        if apache2InstallStatus:
            run("service apache2 start", shell=True)
            try:
                response = urllib.request.urlopen(
                    'http://192.168.1.153/restricted_sites.html')
                while response.status != 200:
                    run('service apache2 restart', shell=True)
                    sleep(5)
            except urllib.error.HTTPError as e:
                print(f"[ERROR] HTTP Error {e.code}: {e.reason}")
                run('service apache2 restart', shell=True)
                print("[INFO] Restarting Apache2 service. Please ensure restricted_sites.html exists in /var/www/html.")
            except Exception as e:
                print(f"[ERROR] Unexpected error: {e}")
        else:
            exit('[ERROR] Apache2 service is not installed. Please install Apache2 and run the server again.')
    except Exception as e:
        exit(f'[ERROR] Failed to start Apache2 service: {e}')

    print('[INFO] Apache2 Server Started (http://localhost:80)')
    print('[INFO] restricted_sites.html copied to /var/www/html.\nEdit the file inside /var/www/html to add or remove restricted sites for clients.')

# main:
# Binds socket to ((HOST, PORT)), listening to connections, accepting new connections, sets a format for connName.
# Sends welcome message to new clients, appends new client's socket objects and connName to the lists.
# Starts 2 threads: One for handling clients and the other for checking connections with clients.
def main():
    try:
        serverSocket.bind((HOST, PORT))  # Bind the socket.
        print(f'[INFO] Server address bound to self ({HOST})')
    except socket.error as error:
        exit(f'[ERROR] Error in Binding the Server:\n\033[31m{error}\033[0m')

    print(f'[INFO] Listening on port {PORT}... (Waiting for connections)')
    serverSocket.listen(50)

    # Close any previous connections if the server restarts:
    for clientSocket in openClientSocketsList:
        clientSocket.close()
    del openClientSocketsList[:], activeAddressesList[:]

    while True:
        try:
            conn, (address, port) = serverSocket.accept()
            openClientSocketsList.append(conn)
            connName = '{}:{}'.format(address, port)
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

# handleClient(conn, connName):
# Main function to receive data from all clients.
# Handles client connections using args from main.
def handleClient(conn, connName):
    while True:
        try:
            data = conn.recv(4096).decode()
            if "MAC" in data:
                timestamp = check_output("date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                print('Possible Man in the Middle attack. Check MitM Logger.log')
                with open(f"{PROJECTPATH}/MitMLog.log", "a+") as MitMLog:
                    MitMLog.write(f"[{timestamp}{TAB_1}\n_{connName}\n+{data}")

            if "restricted" in data:
                timestamp = check_output("date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                print(f'Someone entered a restricted site. Check Restricted Sites Logger.log')
                with open(f'{PROJECTPATH}/Restricted Sites Logger.log', 'a+') as restrictedLog:
                    restrictedLog.write(f"[{timestamp}{TAB_1}\n_{connName}:\n+{data}")
        except Exception as e:
            print(f"[ERROR] Error handling client {connName}: {e}")
            break

# checkConnections:
# Checks what clients are alive by iterating through every client socket object and trying to send a whitespace string.
def checkConnections():
    while True:
        global connectionsCount
        if len(openClientSocketsList) != 0:
            for x, currentSocket in enumerate(openClientSocketsList):
                try:
                    currentSocket.send(' '.encode())
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

# Start of the Script:
if __name__ == '__main__':
    apache2Start()
    main()
