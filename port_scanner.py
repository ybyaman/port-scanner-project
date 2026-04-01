import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: ("FTP", "Insecure protocol; credentials may be exposed if not protected.", "HIGH"),
    22: ("SSH", "Usually safe if configured properly and protected against brute-force attacks.", "LOW"),
    23: ("Telnet", "Highly insecure; traffic is unencrypted.", "HIGH"),
    25: ("SMTP", "Check for open relay misconfiguration.", "MEDIUM"),
    53: ("DNS", "Ensure DNS service is intended to be public.", "LOW"),
    80: ("HTTP", "Consider using HTTPS instead of plain HTTP.", "MEDIUM"),
    110: ("POP3", "Unencrypted email retrieval can be risky.", "HIGH"),
    143: ("IMAP", "Unencrypted email access can be risky.", "HIGH"),
    443: ("HTTPS", "Generally expected for secure web traffic.", "LOW"),
    3306: ("MySQL", "Database ports should not usually be publicly exposed.", "HIGH"),
    3389: ("RDP", "Common target for brute-force attacks.", "HIGH"),
    5432: ("PostgreSQL", "Database ports should be restricted.", "HIGH"),
    8080: ("HTTP-Alt", "May expose admin panels or test services.", "MEDIUM"),
}

TIMEOUT = 0.5


def scan_port(ip: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            service, risk_note, risk_level = COMMON_PORTS.get(
                port,
                ("Unknown", "Review whether this exposed service is necessary.", "MEDIUM")
            )
            return {
                "port": port,
                "service": service,
                "status": "OPEN",
                "risk_note": risk_note,
                "risk_level": risk_level
            }
    except Exception:
        return None
    finally:
        s.close()
    return None


def scan_target(ip: str, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)
        for result in results:
            if result:
                open_ports.append(result)
    return open_ports


def main():
    target = input("Enter target IP or hostname: ").strip()

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Could not resolve target.")
        return

    print(f"\nScanning target: {target} ({ip})")
    print("Please use this only on systems you own or are authorized to test.\n")

    ports_to_scan = list(COMMON_PORTS.keys())
    results = scan_target(ip, ports_to_scan)

    if not results:
        print("No open common ports found.")
        return

    print("Open ports found:\n")
    for item in results:
        print(f"Port {item['port']} ({item['service']}): {item['status']}")
        print(f"Risk Level: {item['risk_level']}")
        print(f"Risk note: {item['risk_note']}\n")


if __name__ == "__main__":
    main()