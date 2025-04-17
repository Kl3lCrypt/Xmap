#!/usr/bin/env python3

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
from threading import Event
import ipaddress
from tqdm import tqdm  # Importar tqdm para la barra de progreso

# Evento global para detener los hilos
stop_event = Event()

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target(s) to scan (Ex: -t 192.168.1.1,192.168.1.2 or 192.168.1.1-192.168.1.5)")
    parser.add_argument("-p", "--port", dest="port", help="Port(s) to scan (Ex: -p 80, 20-100, 22,80,443). Default: Top 100 common ports")
    options = parser.parse_args()

    # Si no se especifican puertos, usar los 100 puertos más comunes
    if not options.port:
        common_ports = "20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,53,67,68,161,162,389,636,1433,1521,5432,6379,27017,11211,5000,8000,8888,9000,9090,9200,9300,27017,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49162,49163,49164,49165,49166,49167,49168,49169,49170,49171,49172,49173,49174,49175,49176,49177,49178,49179,49180,49181,49182,49183,49184,49185,49186,49187,49188,49189,49190,49191,49192,49193,49194,49195,49196,49197,49198,49199"
        # Eliminar duplicados y ordenar los puertos
        unique_ports = sorted(set(map(int, common_ports.split(","))))
        options.port = ",".join(map(str, unique_ports))
        print(colored("[*] No ports specified. Scanning the top 100 common ports.", 'cyan'))

    return options.target, options.port

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
            raise ValueError(f"Invalid subnet: {targets_str}")
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

def parse_ports(ports_str):
    """
    Procesa los puertos en formato de rango, lista o único.
    """
    if "-" in ports_str:
        start, end = map(int, ports_str.split("-"))
        return range(start, end + 1)
    elif "," in ports_str:
        return list(map(int, ports_str.split(",")))  # Convertir a lista de enteros
    else:
        return [int(ports_str)]

def port_scanner(port, host, stop_event):
    """
    Escanea un puerto específico en un host.
    """
    if stop_event.is_set():
        return None  # Salir inmediatamente si se activa stop_event

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)  # Reducir el tiempo de espera a 200 ms
            s.connect((host, port))
            return (host, port, "Open")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def scan_ports(ports, target, no_open_hosts, stop_event):
    """
    Escanea múltiples puertos en un host y muestra los resultados en tiempo real.
    """
    open_ports = []
    headers_printed = False  # Bandera para imprimir las cabeceras solo una vez

    with ThreadPoolExecutor(max_workers=700) as executor:  # Aumentar el número de hilos
        futures = [executor.submit(port_scanner, port, target, stop_event) for port in ports]
        for future in as_completed(futures):
            if stop_event.is_set():
                executor.shutdown(wait=False)  # Detener los hilos inmediatamente
                print(colored("\n[!] Scan interrupted by user.", "red"))
                return

            result = future.result()
            if result:
                open_ports.append(result)

                # Imprimir las cabeceras si aún no se han imprimido
                if not headers_printed:
                    print(
                        colored(f"\n\nHost".ljust(22), 'magenta', attrs=["bold"]) +
                        colored("Port".ljust(10), 'magenta', attrs=["bold"]) +
                        colored("Status", 'magenta', attrs=["bold"])
                    )
                    print(colored("-" * 45, 'grey'))
                    headers_printed = True

                # Mostrar el puerto abierto en tiempo real
                host, port, status = result
                print(
                    colored(f"{host.ljust(20)}", 'green', attrs=["bold"]) +
                    colored(f"{str(port).ljust(10)}", 'blue') +
                    colored(f"{status}", 'yellow')
                )

    # Si hay puertos abiertos, añadir una barra separadora al final
    if open_ports:
        print(colored("-" * 45, 'grey'))
        print("\n")  # Línea separadora final

    # Si no hay puertos abiertos, agregar el host a la lista de no_open_hosts
    if not open_ports:
        no_open_hosts.append(target)

def run(target, stop_event, ports=None):
    """
    Ejecuta el escaneo TCP para un objetivo específico.
    """
    if ports is None:
        # Usar los 100 puertos más comunes si no se especifican
        ports_str = "20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
        print(colored(f"\n[*] No ports specified. Scanning the top 100 common ports.", "yellow", attrs=["bold"]))
    else:
        ports_str = ports

    ports = parse_ports(ports_str)
    targets = parse_targets(target)

    # Eliminar duplicados en los puertos
    ports = sorted(set(ports))

    # Mostrar mensaje de inicio del escaneo
    print(colored(f"\n[+] Scanning targets: {target}\n", 'cyan', attrs=['bold']))

    # Lista para rastrear hosts sin puertos abiertos
    no_open_hosts = []

    # Usar tqdm para mostrar una barra de progreso mientras se escanean las IPs
    with tqdm(
        total=len(targets),
        desc=colored("Scanning targets", 'white', attrs=['bold']),
        unit="host",
        leave=True,
        dynamic_ncols=True,
        bar_format="\033[37m{l_bar}{bar}\033[0m| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
    ) as progress_bar:
        for target in targets:
            if stop_event.is_set():
                break
            scan_ports(ports, target, no_open_hosts, stop_event)
            progress_bar.update(1)

        progress_bar.close()  # Cerrar la barra de progreso correctamente

    # Mostrar mensaje genérico si hay hosts sin puertos abiertos
    if no_open_hosts:
        print(colored(f"\n[!] No open ports were found on some of the scanned hosts.", 'red'))

    print()  # Agregar un salto de línea al final del output

def main():
    target_str, ports_str = get_arguments()
    targets = parse_targets(target_str)  # Process multiple IPs
    ports = parse_ports(ports_str)

    # Formatear el rango o lista de objetivos para mostrar
    formatted_targets = target_str

    # Mostrar mensaje de inicio del escaneo
    print(colored(f"[+] Scanning targets: {formatted_targets}", 'magenta', attrs=['bold']))

    # Lista para rastrear hosts sin puertos abiertos
    no_open_hosts = []

    # Usar tqdm para mostrar una barra de progreso mientras se escanean las IPs
    with tqdm(
        total=len(targets),
        desc=colored("Scanning targets", 'white', attrs=['bold']),  # Texto en blanco y negrita
        unit="host",
        leave=True,  # Mantener la barra en su lugar
        dynamic_ncols=True,  # Ajustar dinámicamente el ancho de la barra
        bar_format="\033[37m{l_bar}{bar}\033[0m| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"  # Barra en blanco
    ) as progress_bar:
        for target in targets:
            scan_ports(ports, target, no_open_hosts, stop_event)
            progress_bar.update(1)  # Actualizar la barra de progreso

    # Mostrar mensaje genérico si hay hosts sin puertos abiertos
    if no_open_hosts:
        print(colored(f"\n[!] No open ports were found on some of the scanned hosts.", 'red'))

    # Agregar un salto de línea al final del output
    print()

if __name__ == '__main__':
    main()
