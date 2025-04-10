
import argparse
import ipaddress
import socket
import subprocess
import threading
import platform
import os

def ping(host, timeout=1):
    """Realiza ping a un host y retorna True si responde"""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "1", "-w", str(timeout * 1000), host],
                                stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def ping_sweep(network, timeout=1):
    """Escanea una red y retorna hosts activos"""
    active_hosts = []
    threads = []
    lock = threading.Lock()

    def ping_host(ip):
        if ping(str(ip), timeout=timeout):
            with lock:
                print(f"[+] Host activo: {ip}")
                active_hosts.append(str(ip))

    for ip in ipaddress.ip_network(network).hosts():
        t = threading.Thread(target=ping_host, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return active_hosts

def scan_port(host, port, timeout=1):
    """Intenta conectar a un puerto específico"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    return port, banner if banner else "Sin banner"
                except:
                    return port, "Sin banner"
    except:
        pass
    return None

def port_scan(host, ports, timeout=1):
    """Escanea puertos en un host específico"""
    open_ports = []
    threads = []
    lock = threading.Lock()

    def scan(p):
        result = scan_port(host, p, timeout)
        if result:
            with lock:
                open_ports.append(result)
                print(f"[+] {host}:{result[0]} abierto - {result[1]}")

    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return open_ports

def parse_ports(ports_input):
    if ports_input.lower() == "all":
        return list(range(1, 65536))
    else:
        return [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]

def main():
    parser = argparse.ArgumentParser(description="Escáner de Red Personalizado")
    parser.add_argument("-n", "--network", required=True, help="Rango de red a escanear (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="80,443", help="Puertos a escanear o 'all'")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    output_path = r"C:\Users\elias\OneDrive\Documentos\redes avanzadas\1.prueba\resultados.txt"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"[~] Realizando ping sweep sobre {args.network}...")
    activos = ping_sweep(args.network)

    all_results = []
    for host in activos:
        print(f"[~] Escaneando puertos de {host}...")
        abiertos = port_scan(host, ports)
        if abiertos:
            for port, banner in abiertos:
                all_results.append(f"{host}:{port} - {banner}")

    with open(output_path, "w", encoding="utf-8") as f:
        for line in all_results:
            f.write(line + "\n")

    print(f"\n[✓] Escaneo completado. Resultados guardados en: {output_path}")

if __name__ == "__main__":
    main()
