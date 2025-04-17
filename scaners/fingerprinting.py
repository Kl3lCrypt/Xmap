import socket
import ssl
import re
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import logging
from colorama import Fore, Style, init

# Configuración de logging (solo mostrar errores)
logging.basicConfig(level=logging.ERROR, format='[%(levelname)s] %(message)s')

# Inicializa colorama
init(autoreset=True)

# Puertos y servicios comunes
COMMON_PORTS = {
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
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    139: "NetBIOS",
    445: "SMB",
    5900: "VNC",
    6379: "Redis",
    5432: "PostgreSQL",
    161: "SNMP",
    389: "LDAP",
    502: "Modbus",
    47808: "BACnet",
    27017: "MongoDB"
}

# Lee el banner completo hasta timeout o cierre
def read_banner(sock, timeout=2, max_bytes=4096):
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
            if len(data) >= max_bytes:
                break
    except socket.timeout:
        pass
    return data.decode(errors="ignore")

# Fingerprinting del banner
def fingerprint_banner(banner):
    patterns = {
        r"Apache/([\d\.]+)": "Apache",
        r"nginx/([\d\.]+)": "Nginx",
        r"OpenSSH[_ ]([\d\.]+)": "OpenSSH",
        r"Exim ([\d\.]+)": "Exim",
        r"Postfix": "Postfix",
        r"MySQL\s+([\d\.]+)": "MySQL",
        r"MariaDB": "MariaDB",
        r"Redis": "Redis",
        r"Microsoft-IIS/([\d\.]+)": "IIS",
        r"MongoDB": "MongoDB",
        r"PostgreSQL": "PostgreSQL",
        r"SMB": "SMB",
        r"VNC": "VNC",
        r"SNMP": "SNMP",
        r"LDAP": "LDAP",
        r"Modbus": "Modbus",
        r"BACnet": "BACnet"
    }
    for regex, name in patterns.items():
        match = re.search(regex, banner, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else "?"
            return f"{name} {version}"
    return "Desconocido"

# Analiza un puerto y retorna resultados
def analyze_port(ip, port):
    service = COMMON_PORTS.get(port, "Desconocido")
    banner = None
    fingerprint = "Desconocido"

    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            if service in ["HTTP", "HTTP-alt"]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = read_banner(sock)
            if banner:
                fingerprint = fingerprint_banner(banner)
    except (socket.timeout, ConnectionRefusedError):
        pass
    except Exception:
        pass

    return {
        "ip": ip,
        "port": port,
        "service": service,
        "banner": banner.strip() if banner else "Sin respuesta",
        "fingerprint": fingerprint
    }

# Escanea múltiples puertos usando un ThreadPoolExecutor
def scan_ports(ip, ports):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(analyze_port, ip, port) for port in ports]
        for future in futures:
            results.append(future.result())
    return results

if __name__ == "__main__":
    ip_input = input("IPs objetivo (ej. 192.168.1.1, 192.168.1.0/30): ").strip()
    port_range = input("Rango de puertos (ej. 20-100): ").strip()
    start, end = map(int, port_range.split("-"))
    ports = list(range(start, end + 1))

    ip_targets = []
    for ip_entry in ip_input.split(","):
        ip_entry = ip_entry.strip()
        try:
            if "/" in ip_entry:
                ip_net = ipaddress.ip_network(ip_entry, strict=False)
                ip_targets.extend([str(ip) for ip in ip_net.hosts()])
            else:
                ip_targets.append(ip_entry)
        except ValueError:
            print(f"{Fore.RED}IP inválida o mal formato: {ip_entry}")

    for ip in ip_targets:
        print(f"\n{Fore.CYAN}== Escaneando {ip} ==")
        results = scan_ports(ip, ports)
        for r in results:
            print(f"{Fore.GREEN}[+] {r['ip']}:{r['port']} -> {Fore.YELLOW}{r['service']}")
            print(f"{Fore.MAGENTA}    Banner: {r['banner']}")
            print(f"{Fore.BLUE}    Fingerprint: {r['fingerprint']}")
