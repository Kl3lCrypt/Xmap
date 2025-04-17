#!/usr/bin/env python3

import warnings
import sys
import ipaddress
import time
from scapy.all import ARP, Ether, srp
import manuf
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored

# Silenciar warnings
warnings.filterwarnings("ignore")

def parse_targets(targets_str):
    """
    Procesa los objetivos en formato CIDR, rango o lista de IPs.
    """
    targets = []
    if "/" in targets_str:  # Subred en formato CIDR
        try:
            network = ipaddress.ip_network(targets_str, strict=False)
            targets = [str(ip) for ip in network.hosts()]  # Generar todas las IPs de la subred
        except ValueError:
            print(f"[!] Invalid subnet: {targets_str}")
            sys.exit(1)
    elif "-" in targets_str:  # Rango de IPs
        start_ip, end_ip = targets_str.split("-")
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        for ip_int in range(int(start_ip), int(end_ip) + 1):
            targets.append(str(ipaddress.IPv4Address(ip_int)))
    elif "," in targets_str:  # Lista de IPs separadas por comas
        targets = [ip.strip() for ip in targets_str.split(",")]
    else:  # Una sola IP
        targets = [targets_str.strip()]
    return targets

def scan_arp_batch(targets):
    """
    Realiza un escaneo ARP para un rango de IPs en un solo paquete.
    """
    results = []
    try:
        # Crear el paquete ARP broadcast para todas las IPs
        arp_request = ARP(pdst=targets)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Enviar el paquete y recibir respuestas
        answered, unanswered = srp(arp_request_broadcast, timeout=1, verbose=False)

        # Crear el objeto MacParser para obtener el fabricante de la MAC
        p = manuf.MacParser()

        # Procesar respuestas
        for sent, received in answered:
            mac_address = received.hwsrc  # Dirección MAC de la respuesta
            fabricante = p.get_manuf(mac_address)  # Obtener el fabricante de la MAC usando `get_manuf()`
            ip_address = received.psrc
            results.append((ip_address, mac_address, fabricante))
    except Exception as e:
        print(f"[!] Error scanning {targets}: {e}")
    return results

def run(target):
    """
    Ejecuta el escaneo ARP para un objetivo específico.
    """
    try:
        # Generar las IPs objetivo
        targets = parse_targets(target)

        # Dividir las IPs en lotes de 50 para optimizar el escaneo
        batch_size = 50
        results = []
        start_time = time.time()

        # Usar ThreadPoolExecutor para procesar lotes en paralelo
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_arp_batch, targets[i:i + batch_size])
                       for i in range(0, len(targets), batch_size)]

            for future in as_completed(futures):
                results.extend(future.result())

        # Mostrar resultados en formato tabular con colores
        print(colored("\n[+] Resultados del escaneo ARP:\n", "cyan", attrs=["bold"]))
        print(colored("IP".ljust(20), "magenta", attrs=["bold"]) +
              colored("MAC".ljust(20), "magenta", attrs=["bold"]) +
              colored("Fabricante".ljust(30), "magenta", attrs=["bold"]))
        print(colored("-" * 70, "grey"))

        for ip_address, mac_address, fabricante in results:
            ip_col = colored(ip_address.ljust(20), "green", attrs=["bold"])
            mac_col = colored(mac_address.ljust(20), "blue")
            fabricante_col = colored((fabricante or "Desconocido").ljust(30), "yellow")
            print(ip_col + mac_col + fabricante_col)

        # Mostrar tiempo total del escaneo
        end_time = time.time()
        print(colored(f"\n[+] Escaneo ARP completado en {end_time - start_time:.2f} segundos.\n", "cyan", attrs=["bold"]))

    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(1)

