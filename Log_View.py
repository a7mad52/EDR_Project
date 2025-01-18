import tkinter as tk
from tkinter import ttk
import threading
import socket

class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EDR Log Viewer")
        self.root.geometry("1000x600")
        self.root.configure(bg="#2E3440")  # Set background color for the main window

        # Socket connection to the EDR server
        self.server_host = "192.168.1.153"
        self.server_port = 1111
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Real-time log capture control
        self.capture_active = False
        self.sequence_number = 1  # Counter for sequence numbers

        # Define colors and fonts
        self.bg_color = "#2E3440"  # Dark background
        self.fg_color = "#D8DEE9"  # Light text
        self.button_bg = "#5E81AC"  # Updated button background (softer blue)
        self.button_fg = "#ECEFF4"  # Button text
        self.button_active_bg = "#81A1C1"  # Active button background
        self.table_bg = "#3B4252"  # Table background
        self.table_fg = "#E5E9F0"  # Table text
        self.status_bg = "#434C5E"  # Status label background
        self.status_fg = "#88C0D0"  # Status label text (cyan)
        self.font = ("Segoe UI", 10)  # Updated font for better readability
        self.bold_font = ("Segoe UI", 10, "bold")  # Bold font for buttons

        self.create_widgets()
        self.connect_to_server()

    def create_widgets(self):
        # Frame for buttons (vertical layout)
        button_frame = tk.Frame(self.root, bg=self.bg_color)
        button_frame.pack(side=tk.LEFT, fill=tk.Y, padx=15, pady=15)

        # Buttons for controlling real-time capture and log management
        self.start_button = tk.Button(
            button_frame, text="Start Capture", command=self.start_capture, width=18,
            bg=self.button_bg, fg=self.button_fg, font=self.bold_font, relief=tk.FLAT,
            activebackground=self.button_active_bg, activeforeground=self.button_fg
        )
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(
            button_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED, width=18,
            bg=self.button_bg, fg=self.button_fg, font=self.bold_font, relief=tk.FLAT,
            activebackground=self.button_active_bg, activeforeground=self.button_fg
        )
        self.stop_button.pack(pady=10)

        self.clear_button = tk.Button(
            button_frame, text="Clear Screen", command=self.clear_table, width=18,
            bg="#BF616A", fg=self.button_fg, font=self.bold_font, relief=tk.FLAT,  # Red for clear button
            activebackground="#D08770", activeforeground=self.button_fg
        )
        self.clear_button.pack(pady=10)

        # Frame for the log table and scrollbar
        table_frame = tk.Frame(self.root, bg=self.bg_color)
        table_frame.pack(pady=15, padx=15, expand=True, fill=tk.BOTH)

        # Log data display table with columns
        self.tree = ttk.Treeview(
            table_frame, columns=("No.", "Type", "Timestamp", "IP Address:Port", "Message"), show="headings",
            style="Custom.Treeview"
        )
        self.tree.heading("No.", text="No.", anchor=tk.W)
        self.tree.heading("Type", text="Type", anchor=tk.W)
        self.tree.heading("Timestamp", text="Timestamp", anchor=tk.W)
        self.tree.heading("IP Address:Port", text="IP Address:Port", anchor=tk.W)
        self.tree.heading("Message", text="Message", anchor=tk.W)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        # Add a vertical scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Style the Treeview
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Custom.Treeview",
                        background=self.table_bg,
                        foreground=self.table_fg,
                        fieldbackground=self.table_bg,
                        font=self.font,
                        rowheight=25)
        style.map("Custom.Treeview",
                  background=[("selected", "#4C566A")],  # Highlight color for selected rows
                  foreground=[("selected", self.table_fg)])

        # Status label
        self.status_label = tk.Label(
            self.root, text="Status: Ready", fg=self.status_fg, bg=self.status_bg,
            font=("Segoe UI", 12, "bold"), padx=15, pady=10
        )
        self.status_label.pack(pady=10, fill=tk.X)

    def connect_to_server(self):
        """Connect to the EDR server."""
        try:
            self.client_socket.connect((self.server_host, self.server_port))
            print("[INFO] Connected to the EDR server.")
            self.status_label.config(text="Status: Connected to server", fg="#A3BE8C")  # Green for success
        except Exception as e:
            print(f"[ERROR] Failed to connect to the EDR server: {e}")
            self.status_label.config(text="Status: Connection failed", fg="#BF616A")  # Red for failure

    def start_capture(self):
        """Start real-time log capture."""
        if not self.capture_active:
            self.capture_active = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Capturing logs...", fg="#A3BE8C")  # Green for active status

            # Start a thread to receive logs from the server
            self.receive_thread = threading.Thread(target=self.receive_logs)
            self.receive_thread.daemon = True
            self.receive_thread.start()

    def stop_capture(self):
        """Stop real-time log capture."""
        if self.capture_active:
            self.capture_active = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Capture stopped", fg="#BF616A")  # Red for stopped status

    def receive_logs(self):
        """Receive logs from the EDR server."""
        while self.capture_active:
            try:
                data = self.client_socket.recv(4096).decode()
                if data:
                    self.process_log_entry(data)
            except Exception as e:
                print(f"[ERROR] Error receiving logs: {e}")
                break

    def process_log_entry(self, log_data):
        """Process a single log entry and insert it into the table."""
        # Initialize variables
        timestamp = None
        ip_address = None
        message = None
        log_type = None  # Initialize log type

        # Split the log entry into lines
        log_lines = log_data.split('\n')
        for log_line in log_lines:
            if log_line.startswith('['):  # Timestamp
                timestamp = self.extract_timestamp(log_line)
            elif log_line.startswith('_'):  # IP address:Port
                ip_address = self.extract_ip_address(log_line)
            elif log_line.startswith('+'):  # Message
                message = self.extract_message(log_line)

        # Determine the log type based on the message
        if message and "Entered a restricted website" in message:
            log_type = "Restricted Page"
        elif message and "Potential SYN Flood DoS attack detected" in message:
            log_type = "DoS Attack"

        # Validate the log entry
        if not timestamp or not ip_address or not message or not log_type:
            return  # Skip this log entry if any field is missing or invalid

        # Insert the complete log entry into the table with a sequence number
        self.tree.insert("", "end", values=(self.sequence_number, log_type, timestamp, ip_address, message))
        self.sequence_number += 1  # Increment the sequence number

    def extract_timestamp(self, line):
        """Extract the timestamp from the log entry."""
        if line.startswith("[") and len(line) > 1:
            return line[1:].strip()  # Extract and strip the timestamp
        return None  # Return None if the timestamp is invalid

    def extract_ip_address(self, line):
        """Extract the IP address and port from the log entry."""
        if line.startswith("_") and len(line) > 1:
            return line[1:].strip()  # Extract and strip the IP address
        return None  # Return None if the IP address is invalid

    def extract_message(self, line):
        """Extract the log message from the log entry."""
        if line.startswith("+") and len(line) > 1:
            return line[1:].strip()  # Extract and strip the message
        return None  # Return None if the message is invalid

    def clear_table(self):
        """Clear all entries from the table."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.sequence_number = 1  # Reset the sequence number
        self.status_label.config(text="Status: Screen cleared", fg="#88C0D0")  # Cyan for cleared status

if __name__ == "__main__":
    root = tk.Tk()
    app = LogViewerApp(root)
    root.mainloop()
