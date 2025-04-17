import sys
from scaners.scan_arp import run as arp_scan
from scaners.scan_icmp import run as icmp_scan
from scaners.scan_tcp import run as tcp_scan  # Importar el escaneo TCP

def handle_scan(scan_type, target, stop_event, ports=None):
    """Gestiona el tipo de escaneo y lo ejecuta"""
    if scan_type == "arp":
        arp_scan(target)
    elif scan_type == "icmp":
        icmp_scan(target, stop_event)
    elif scan_type == "tcp":
        tcp_scan(target, stop_event, ports)  # Pasar los puertos al escáner TCP
    else:
        print(f"[!] Tipo de escaneo no soportado: {scan_type}")
        sys.exit(2)

