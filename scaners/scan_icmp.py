import os
import sys
import time
from scapy.all import IP, ICMP, sr1, conf
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import math
import warnings
import logging

# Desactivar los mensajes de advertencia de Scapy
conf.verb = 0

# Configurar el sistema de logging de Scapy para ignorar warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Silenciar warnings de Python
warnings.filterwarnings("ignore")

def parse_target(target_str):
    """Convierte la cadena de IP en una lista de IPs a escanear."""
    if "," in target_str:
        base_ip, last_octets = target_str.rsplit(".", 1)
        return [f"{base_ip}.{octet.strip()}" for octet in last_octets.split(",")]

    target_str_splitted = target_str.split('.')
    first_three_octets = ".".join(target_str_splitted[:3])

    if len(target_str_splitted) == 4:
        if "-" in target_str_splitted[3]:
            start, end = target_str_splitted[3].split("-")
            return [f"{first_three_octets}.{i}" for i in range(int(start), int(end) + 1)]
        else:
            return [target_str]
    else:
        print(colored(f"\n[!] Formato de IP Inválido", "red"))
        sys.exit(2)

def host_discovery(target, stop_event):
    """
    Realiza un ping a un host, muestra el resultado si es alcanzable y estima el sistema operativo.
    """
    if stop_event.is_set():
        return
    if target.endswith('.255'):  # Ignorar direcciones de broadcast
        return

    try:
        for attempt in range(2):  # Intentar 1 veces
            if stop_event.is_set():
                return

            # Medir el tiempo de ida y vuelta (RTT)
            start_time = time.time()
            packet = IP(dst=target) / ICMP()
            response = sr1(packet, timeout=0.5, verbose=0)  # Timeout reducido a 0.5 segundos
            end_time = time.time()

            if response:
                rtt = (end_time - start_time) * 1000  # Convertir a milisegundos
                ttl = response.ttl  # Obtener el TTL de la respuesta
                os_guess = "Desconocido"

                # Estimar el sistema operativo basado en el TTL
                if math.isclose(ttl, 128, abs_tol=10):  # TTL cercano a 128
                    os_guess = "Windows"
                elif math.isclose(ttl, 64, abs_tol=10):  # TTL cercano a 64
                    os_guess = "Linux"

                # Formatear las columnas
                ip_col = colored(target.ljust(20), "green", attrs=["bold"])
                time_col = colored(f"{rtt:.2f} ms".ljust(18), "blue")  # Mostrar RTT con 2 decimales
                os_col = colored(os_guess.ljust(10), "yellow")
                print(ip_col + time_col + os_col)
                return  # Salir del bucle si el host responde

        # Si no hay respuesta válida después de 2 intentos, no imprimir nada

    except Exception as e:
        print(colored(f"[!] Error con la IP {target}: {str(e)}", "red"))

def run(target, stop_event):
    """Función principal que ejecuta el escáner ICMP en paralelo."""
    targets = parse_target(target)
    
    # Imprimir la cabecera de la tabla
    print(colored("\n[+] Hosts activos (ICMP):\n", "cyan", attrs=["bold"]))
    print(colored("IP".ljust(20) + "Tiempo (ms)".ljust(18) + "SO (TTL)".ljust(10), "magenta", attrs=["bold"]))
    print(colored("-" * 50, "grey"))
    max_threads = 100
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(lambda ip: host_discovery(ip, stop_event), targets)
