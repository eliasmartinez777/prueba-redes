import socket
import ipaddress
import concurrent.futures
import argparse
import os
import platform
from datetime import datetime

def ping(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = f"ping {param} 1 {host} > nul 2>&1" if platform.system().lower() == "windows" else f"ping {param} 1 {host} > /dev/null 2>&1"
    return os.system(command) == 0

def ping_sweep(network):
    print(f"[+] Iniciando ping sweep en la red: {network}")
    red = ipaddress.ip_network(network, strict=False)
    activos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        resultados = {executor.submit(ping, str(host)): str(host) for host in red.hosts()}
        for future in concurrent.futures.as_completed(resultados):
            ip = resultados[future]
            try:
                if future.result():
                    print(f"[+] Host activo: {ip}")
                    activos.append(ip)
            except Exception as e:
                print(f"[!] Error al hacer ping a {ip}: {e}")
    return activos

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    s.sendall(b'\n')
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "Sin banner"
                return (port, banner)
    except Exception as e:
        return None

def port_scan(host, ports):
    print(f"[+] Escaneando puertos en {host}")
    abiertos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        resultados = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(resultados):
            resultado = future.result()
            if resultado:
                port, banner = resultado
                print(f"[+] Puerto abierto: {port} - Banner: {banner}")
                abiertos.append((port, banner))
    return abiertos

def main():
    parser = argparse.ArgumentParser(description="Escáner de Red tipo Nmap")
    parser.add_argument("-n", "--network", help="Red a escanear (ej: 192.168.100.0/24)", required=True)
    parser.add_argument("-p", "--ports", help="Puertos a escanear (ej: 23,80,7547)", default="23,80,7547")
    parser.add_argument("-o", "--output", help="Archivo de salida (opcional)", default=None)
    args = parser.parse_args()

    puertos = list(map(int, args.ports.split(",")))
    hosts_activos = ping_sweep(args.network)

    resultados = {}
    for host in hosts_activos:
        abiertos = port_scan(host, puertos)
        resultados[host] = abiertos

    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"Resultado del escaneo - {datetime.now()}\n\n")
            for host, puertos in resultados.items():
                f.write(f"Host: {host}\n")
                for port, banner in puertos:
                    f.write(f"  Puerto {port}: {banner}\n")
                f.write("\n")
        print(f"[+] Resultados guardados en {args.output}")

if __name__ == "__main__":
    main()
