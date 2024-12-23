import nmap
import socket
import requests
from scapy.all import ARP, Ether, srp
import sys

def banner():
    print("="*50)
    print("  CyberSecurity Tool - Vulnerability Detection")
    print("  Author: Your Name")
    print("="*50)

def port_scanner(target):
    print(f"Scanning open ports on {target}...\n")
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1024', '-sS')
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print("Open Ports:")
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol].keys()
            for port in ports:
                print(f"  Port {port} ({protocol}): Open")
    print("\nPort scanning complete.")

def detect_common_vulnerabilities(target):
    print(f"Checking for common vulnerabilities on {target}...")
    # Example check: CVE-2023-12345 (Dummy Check)
    test_url = f"http://{target}/test"
    try:
        response = requests.get(test_url, timeout=5)
        if "vulnerable" in response.text.lower():
            print("[!] Vulnerability detected: CVE-2023-12345")
        else:
            print("[-] No vulnerability detected for CVE-2023-12345")
    except requests.exceptions.RequestException as e:
        print(f"Error while checking vulnerabilities: {e}")

def arp_scan(network):
    print(f"Performing ARP scan on network {network}...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Devices Found:")
    for client in clients:
        print(f"IP: {client['ip']} - MAC: {client['mac']}")

def main():
    banner()
    print("Choose an option:")
    print("[1] Scan Open Ports")
    print("[2] Detect Common Vulnerabilities")
    print("[3] Perform ARP Scan on Network")
    print("[4] Exit")
    
    choice = input("Enter your choice: ")
    if choice == '1':
        target = input("Enter the target IP address: ")
        port_scanner(target)
    elif choice == '2':
        target = input("Enter the target IP address: ")
        detect_common_vulnerabilities(target)
    elif choice == '3':
        network = input("Enter the network range (e.g., 192.168.1.0/24): ")
        arp_scan(network)
    elif choice == '4':
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice! Please try again.")
        main()

if __name__ == "__main__":
    main()
