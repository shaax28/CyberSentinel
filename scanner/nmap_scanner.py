import nmap
import sqlite3
from datetime import datetime

DB_NAME = "cybersentinel.db"


def save_result(target, protocol, port, data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_results
        (target, port, protocol, state, service, product, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        port,
        protocol,
        data.get("state"),
        data.get("name", "unknown"),
        data.get("product", ""),
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def scan_target(target):
    scanner = nmap.PortScanner()

    print(f"\n[+] Scanning: {target}")
    print("[+] Please wait...\n")

    scanner.scan(target, "1-1024", arguments="-sV")

    for host in scanner.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scanner[host].state()}")

        for protocol in scanner[host].all_protocols():

            for port in sorted(scanner[host][protocol].keys()):
                data = scanner[host][protocol][port]

                print(
                    f"Port: {port} | "
                    f"State: {data.get('state')} | "
                    f"Service: {data.get('name', 'unknown')}"
                )

                save_result(
                    host,
                    protocol,
                    port,
                    data
                )

    print("\n[+] Scan results saved to CyberSentinel database.")


if __name__ == "__main__":
    target = input(
        "Enter authorized target (example: 127.0.0.1): "
    )

    scan_target(target)