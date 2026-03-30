"""
Author: Thomas Osorno
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print system info
print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Stores common port numbers and their associated service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using these decorators allows for data validation and encapsulation while maintaining a clean interface. 
    # It ensures the target cannot be set to an empty string via the setter logic, protecting the object from invalid states 
    # while allowing the user to access it like a regular attribute.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses the target initialization logic by calling super().__init__(target) within its own constructor. 
# This inheritance allows the child class to utilize the private __target property and its associated getter/setter logic 
# without needing to redefine those components from scratch.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        # Q4: What would happen without try-except here?
        # Removing these blocks would cause the program to crash immediately upon encountering a network error, such as 
        # a host being unreachable or a connection timing out. Unhandled exceptions would terminate the script, 
        # preventing the scanner from completing the remaining ports in the specified range.
        try:
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading enables the program to initiate multiple connection attempts concurrently rather than waiting for each 
    # 1-second timeout to resolve sequentially. Scanning 1024 ports one by one could take over 17 minutes, while 
    # threading reduces the total execution time to just a few seconds by performing tasks in parallel.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("Database error:", e)

def load_past_scans():
    try:
        if not os.path.exists("scan_history.db"):
            print("No past scans found.")
            return

        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT scan_date, target, port, service, status FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[0]}] {row[1]} : Port {row[2]} ({row[3]}) - {row[4]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

if __name__ == "__main__":
    try:
        target_input = input("Enter target IP (default 127.0.0.1): ")
        target_ip = target_input if target_input != "" else "127.0.0.1"

        start = int(input("Enter start port (1-1024): "))
        end = int(input("Enter end port (1-1024): "))

        if start < 1 or end > 1024 or end < start:
            print("Port must be between 1 and 1024.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start} to {end}...")
            
            scanner.scan_range(start, end)
            open_ports = scanner.get_open_ports()

            print(f"\n--- Scan Results for {target_ip} ---")
            for p, s, svc in open_ports:
                print(f"Port {p}: {s} ({svc})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target_ip, scanner.scan_results)

            if input("Would you like to see past scan history? (yes/no): ").lower() == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# I would add a "Service Filter" feature that allows users to display only ports with recognized services. 
# This would use a list comprehension like [res for res in self.scan_results if res[2] != "Unknown"] to 
# quickly isolate significant traffic types for the security professional.
# Diagram: See diagram_101513272.png in the repository root