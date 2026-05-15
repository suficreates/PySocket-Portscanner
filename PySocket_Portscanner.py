import socket
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init

init(autoreset=True)

# ------------------ PORT DATA ------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}

RISK_LEVELS = {
    21: "Medium (FTP - insecure)",
    22: "Low (SSH - secure if configured)",
    23: "High (Telnet - insecure)",
    80: "Low (HTTP)",
    443: "Low (HTTPS)",
    445: "High (SMB - common target)",
    3389: "High (RDP - brute force target)"
}

ATTACK_HINTS = {
    21: "FTP may allow anonymous login → Try brute force",
    22: "SSH → Possible brute force attack",
    23: "Telnet → Unencrypted → HIGH RISK",
    80: "HTTP → Check for XSS, SQL Injection",
    443: "HTTPS → Check SSL misconfigurations",
    445: "SMB → Vulnerable to EternalBlue",
    3389: "RDP → Target for brute force attacks"
}


# ------------------ HELPERS ------------------

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(Fore.RED + "Invalid target!")
        return None


def identify_service_from_banner(banner):
    banner = banner.lower()
    banner = banner.split("\n")[0]
    if "anonymous" in banner and "no anonymous" not in banner:
        ATTACK_HINTS=Fore.YELLOW+"anonymous login allowed ⚠️ HIGH RISK"
    if "pure-ftpd" in banner:
        return "pure-ftpd server"      
    if "apache" in banner:
        return "Apache Web Server"
    elif "nginx" in banner:
        return "Nginx Web Server"
    elif "openssh" in banner:
        return "OpenSSH"
    elif "microsoft" in banner:
        return "Microsoft Service"
    else:
        return "Unknown Service"


def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = "No banner"

            try:
                if port == 80:
                    sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").split("\n")[0]

                elif port == 443:
                    banner = "HTTPS (SSL/TLS - no plain banner)"

                else:
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()

            except:
                banner = "No banner"

            sock.close()
            return port, service, banner

        sock.close()

    except:
        pass

    return None
    
def detect_os(open_ports):
    ports = [p[0] for p in open_ports]

    if 445 in ports or 139 in ports:
        return "Windows"
    elif 22 in ports:
        return "Linux/Unix"
    else:
        return "Unknown"

# ------------------ MAIN RUN ------------------

def run():
   

    target_input = input("Enter target (IP or domain, e.g., google.com): ")
    target = resolve_target(target_input)

    if not target:
        return

    print(Fore.YELLOW + f"Resolved IP: {target}")

    # -------- Scan Mode --------
    try:
        print("\n1. Quick Scan (1–1024) : (1)")
        print("2. Full Scan (1–65535) : (2)")
        print("3. Custom Scan : (3)")

        mode = input("Choose scan mode: ")

        if mode == "1":
            start_port, end_port = 1, 1024
        elif mode == "2":
            start_port, end_port = 1, 65535
        else:
            start_port = int(input("Start port: "))
            end_port = int(input("End port: "))

        
    except ValueError:
        print(Fore.RED + "Invalid port range!")
        return

    save_choice = input("Save results to file? (y/n): ").lower()
    print(Fore.YELLOW + f"\nScanning {target} from port {start_port} to {end_port}... \nplease wait 🔍")

    
    start_time = time.time()
    open_ports = []

    # -------- Scanning --------
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: scan_port(target, port),
                               range(start_port, end_port + 1))

        for result in results:
            if result:
                port, service, banner = result
                open_ports.append(result)

                detected = identify_service_from_banner(banner)
                risk = RISK_LEVELS.get(port, "Unknown")
                hint = ATTACK_HINTS.get(port, "No known attack")

                print(Fore.GREEN + f"[OPEN] Port {port} ({service})")
                print(Fore.CYAN + f" Detected: {detected}")
                os_guess = detect_os(open_ports)
                print(Fore.CYAN + f"Detected OS: {os_guess}")
                print(Fore.RED + f" Risk: {risk}")
                print(Fore.BLUE + f" Banner: {banner}")
                print(Fore.MAGENTA + f" Attack Insight: {hint}")

                if port > 1024:
                    print(Fore.YELLOW + "⚠️ Uncommon port detected!")

                print()

                time.sleep(0.03)  # stealth delay

    end_time = time.time()

    print(Fore.MAGENTA + f"\nScan completed in {round(end_time - start_time, 2)} seconds")

    # -------- Summary --------
    high_risk = 0

    for port, service, banner in open_ports:
        if port in [23, 445, 3389]:
            high_risk += 1

    print("\n===== SECURITY SUMMARY =====")
    print(f"Total open ports: {len(open_ports)}")
    print(f"High risk ports: {high_risk}")

    if high_risk > 0:
        print(Fore.RED + "⚠️ System may be vulnerable!")
    else:
        print(Fore.GREEN + "System looks relatively secure.")

    if not open_ports:
        print(Fore.RED + "No open ports found.")

    # -------- Save File --------
    if save_choice == "y":
        with open("scan_results.txt", "w") as f:
            for port, service, banner in open_ports:
                f.write(f"Port {port} ({service}) - {banner}\n")

        print(Fore.YELLOW + "Results saved to scan_results.txt")

    # -------- Detailed Report --------
    with open(f"report_{target}.txt", "w") as f:
        f.write("=== CyberGuard Toolkit Report ===\n")
        f.write(f"Target: {target}\n")
        f.write(f"Open Ports: {len(open_ports)}\n\n")

        for port, service, banner in open_ports:
            risk = RISK_LEVELS.get(port, "Unknown")
            hint = ATTACK_HINTS.get(port, "N/A")

            f.write(f"Port {port} ({service})\n")
            f.write(f"Risk: {risk}\n")
            f.write(f"Banner: {banner}\n")
            f.write(f"Attack Insight: {hint}\n\n")

    print(Fore.GREEN + f"\nReport saved as report_{target}.txt")


# ------------------ START ------------------

if __name__ == "__main__":
    run()
