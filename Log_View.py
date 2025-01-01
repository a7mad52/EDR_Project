import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import threading
import time
import re

class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Management Tool")
        self.root.geometry("900x600")

        self.selected_log_file = None  # Variable to store selected log file path
        self.create_widgets()

    def create_widgets(self):
        # Button to open file dialog and select log file
        self.select_file_button = tk.Button(self.root, text="Select Log File", command=self.select_log_file)
        self.select_file_button.pack(pady=10)

        # Log data display table with columns
        self.tree = ttk.Treeview(self.root, columns=("Timestamp", "IP Address:Port", "Message", "MAC Address"), show="headings")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.heading("IP Address:Port", text="IP Address:Port")
        self.tree.heading("Message", text="Message")
        self.tree.heading("MAC Address", text="MAC Address")
        self.tree.pack(pady=10, expand=True, fill=tk.BOTH)

        # Auto-refresh button
        self.auto_refresh_button = tk.Button(self.root, text="Enable Auto-Refresh", command=self.toggle_auto_refresh)
        self.auto_refresh_button.pack(pady=10)

        # Status label
        self.status_label = tk.Label(self.root, text="Status: Ready", fg="green")
        self.status_label.pack(pady=5)

        self.auto_refresh = False
        self.auto_refresh_thread = None

    def select_log_file(self):
        # Open a file dialog to select a log file
        file_path = filedialog.askopenfilename(title="Select a Log File", filetypes=[("Log Files", "*.log")])
        if file_path:
            self.selected_log_file = file_path
            self.status_label.config(text=f"Selected file: {file_path}", fg="green")
            self.update_logs()

    def update_logs(self):
        if not self.selected_log_file:
            self.status_label.config(text="Error: No log file selected", fg="red")
            return

        self.clear_table()

        # Open log file and read lines
        try:
            with open(self.selected_log_file, "r") as file:
                lines = file.readlines()
                
                # Initialize variables to hold the extracted data
                timestamp = None
                ip_address = None
                message = None
                mac_address = None

                # Process each line and match the format
                for i, line in enumerate(lines):
                    line = line.strip()  # Clean up the line to remove any unwanted whitespace

                    if line.startswith('['):  # Timestamp
                        timestamp = self.extract_timestamp(line)
                    elif line.startswith('_'):  # IP address:Port
                        ip_address = self.extract_ip_address(line)
                    elif line.startswith('+'):  # Message
                        message = self.extract_message(line)
                    elif line.startswith('('):  # MAC Address
                        mac_address = self.extract_mac_address(line)

                    # Once all fields are gathered, insert into table (when all 4 parts are collected)
                    if timestamp and ip_address and message and mac_address:
                        self.tree.insert("", "end", values=(timestamp, ip_address, message, mac_address))
                        # Reset after insertion to handle the next block of log data
                        timestamp, ip_address, message, mac_address = None, None, None, None
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", fg="red")

    def extract_timestamp(self, line):
        # Trim whitespace to ensure we're not matching with extra spaces
        return line[1:].strip() if line.startswith("[") else "Unknown Timestamp"


    def extract_ip_address(self, line):
        # Extract the IP address and port from the line
        return line[1:].strip() if line.startswith("_") else "Unkown IP Address"

    def extract_message(self, line):
        # Extract the log message (everything after the +)
        return line[1:].strip() if line.startswith("+") else "No message"

    def extract_mac_address(self, line):
        # Improved MAC address extraction (matches format like: 00-0c-29-05-08-1b)
        return line[1:].strip() if line.startswith("(") else "Unkown Mac Address"

    def clear_table(self):
        # Clear the table before updating
        for item in self.tree.get_children():
            self.tree.delete(item)

    def toggle_auto_refresh(self):
        if self.auto_refresh:
            self.auto_refresh = False
            self.auto_refresh_button.config(text="Enable Auto-Refresh")
            self.status_label.config(text="Status: Auto-refresh disabled", fg="red")
            if self.auto_refresh_thread:
                self.auto_refresh_thread.join()
        else:
            self.auto_refresh = True
            self.auto_refresh_button.config(text="Disable Auto-Refresh")
            self.status_label.config(text="Status: Auto-refresh enabled", fg="green")
            self.auto_refresh_thread = threading.Thread(target=self.auto_refresh_logs)
            self.auto_refresh_thread.start()

    def auto_refresh_logs(self):
        while self.auto_refresh:
            self.update_logs()
            time.sleep(5)  # Refresh every 5 seconds

if __name__ == "__main__":
    root = tk.Tk()
    app = LogViewerApp(root)
    root.mainloop()
