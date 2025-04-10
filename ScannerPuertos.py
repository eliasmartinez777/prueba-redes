import socket #El módulo socket te permite trabajar con redes y conexiones en Python, usando los protocolos TCP/IP y UDP.
import concurrent.futures #Este módulo sirve para ejecutar tareas en paralelo fácilmente, usando varios hilos (o procesos).
import ipaddress #Este módulo permite manejar direcciones IP y subredes de forma sencilla y segura.


def host_activo(ip): #Verifica si un host está activo intentando conectarse al puerto 80 o 443
    for port in [80, 443]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Crea un socket TCP que se usará para intentar conectarse a un puerto de la IP proporcionada (host).
                s.settimeout(0.5) #Establece un tiempo de espera de 0.5 segundos para la conexión. Si no conseguimos conectarnos al puerto en ese tiempo, el intento se considera fallido.
                result = s.connect_ex((str(ip), port)) #Intenta conectar el socket al puerto específico de la IP (host).
                if result == 0: #Si result es igual a 0, significa que se pudo conectar al puerto, es decir, el puerto está abierto.
                    return True
        except:
            pass
    return False


def scan_port(host, port): #Escanea un puerto en un host dado.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Crea un socket TCP que se usará para intentar conectarse a un puerto de la IP proporcionada (host).
            s.settimeout(1) ##Establece un tiempo de espera de 1 segundo para la conexión. Si no conseguimos conectarnos al puerto en ese tiempo, el intento se considera fallido.
            result = s.connect_ex((host, port)) #Intenta conectar el socket al puerto específico de la IP (host).
            if result == 0: #Si result es igual a 0, significa que se pudo conectar al puerto, es decir, el puerto está abierto.
                return f"[+] Puerto {port} abierto"
    except Exception as e: #Si ocurre un error al intentar conectar (por ejemplo, si el host está apagado, o si hay un error de red), se captura el error.
        return f"Error al escanear el puerto {port}: {e}" #Si ocurre un error, devuelve un mensaje con el puerto y la descripción del error (e).
    return None #Si el puerto no está abierto (es decir, no se puede conectar) o si hubo un error, la función simplemente devuelve None.


def scan_ports(host, ports): #Escanea una lista de puertos en un host usando hilos para mayor rapidez.
    print(f"\nEscaneando puertos en {host}...") #nos imprime el resultado 
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: #Esta es una clase que nos permite ejecutar funciones en hilos (threads), lo que significa que podemos hacer varias tareas al mismo tiempo.
        results = executor.map(lambda p: scan_port(host, p), ports) #ejecuta la función proporcionada (en este caso, scan_port) para cada elemento de la lista ports, de manera concurrente (en paralelo, usando hilos).


    for result in results:
        if result:
            print(result)


def escanear_red(red):# Escanea todos los hosts de una subred para encontrar cuáles están activos. (Este seria el equivalente al ping_sweep sugerido)
    print(f"[+] Escaneando red: {red}")
    red_obj = ipaddress.ip_network(red, strict=False)
    #ip_network(red): Esta función crea un objeto de red a partir de una cadena red que representa una subred, por ejemplo, "192.168.1.0/24".
    #ipaddress: Este es un módulo en Python que se utiliza para trabajar con direcciones y redes IP (tanto IPv4 como IPv6). Proporciona herramientas para analizar, crear y manipular direcciones IP y subredes.
    #strict=False: El parámetro strict determina cómo la función maneja redes incorrectas o inválidas.
    hosts_activos = []


    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        resultados = list(executor.map(host_activo, red_obj.hosts()))
     # with: Usar with garantiza que el recurso (en este caso, el ThreadPoolExecutor) se administre correctamente, es decir, se inicie y cierre de forma eficiente. No tienes que preocuparte por cerrar el executor manualmente.
     # concurrent.futures.ThreadPoolExecutor: Esta clase se utiliza para ejecutar funciones en hilos (threads) de manera concurrente. Aquí, estamos utilizando hilos para realizar múltiples tareas a la vez, lo que acelera el proceso de escanear varios hosts al mismo tiempo.
     # max_workers=50: Esto significa que se utilizarán hasta 50 hilos al mismo tiempo para realizar las tareas. Si hay 50 tareas (verificar si los hosts están activos), se ejecutarán simultáneamente, lo que mejora la velocidad del proceso.
     # executor.map():Esta función permite ejecutar una función (en este caso, host_activo) para cada elemento de una lista (en este caso, todos los hosts de la subred). executor.map() distribuye esas tareas entre los hilos disponibles (50 hilos en este caso) y ejecuta la función de manera concurrente.
     # host_activo: Es la función que verifica si un host (en este caso, una dirección IP) está activo. Se ejecutará en paralelo para cada host en la subred.
     # red_obj.hosts(): red_obj.hosts() genera todas las direcciones IP útiles de la subred (excluyendo la dirección de red y la dirección de broadcast). Esta es la lista de hosts que vamos a verificar.



    for ip, activo in zip(red_obj.hosts(), resultados):
        if activo:
            print(f"[✓] Host activo encontrado: {ip}")
            hosts_activos.append(str(ip))

     # red_obj.hosts(): Esta es una lista de todas las direcciones IP válidas (útiles) dentro de la subred, excluyendo la dirección de red y la de broadcast.
     # if activo: Este condicional verifica si activo es True, es decir, si el host está activo.
     # Aquí, la dirección IP del host activo se añade a la lista hosts_activos. str(ip) convierte la dirección IP en cadena de texto para agregarla correctamente a la lista.

    
    return hosts_activos

if __name__ == "__main__": #Este condicional comprueba si el script está siendo ejecutado directamente. Si es así, el código dentro de ese bloque se ejecutará. Si el script se importa como módulo, ese código no se ejecuta.
    red_input = input("Ingresa la red a escanear (ej. 192.168.1.0/24): ") #La función input() se utiliza para pedir entrada de datos al usuario. El mensaje entre comillas ("Ingresa la red a escanear...") es el texto que se mostrará al usuario para indicarle qué debe
    puertos_comunes = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389] #Es una lista que contiene una serie de puertos comunes que suelen estar abiertos en muchos dispositivos. Los puertos en la lista incluyen:

    hosts = escanear_red(red_input) #Llama a la función escanear_red con la red que el usuario ingresó (por ejemplo, 192.168.1.0/24), Esa función devuelve una lista de hosts activos (IPs que respondieron).

    for host in hosts:
        scan_ports(host, puertos_comunes) #Para cada una, llama a scan_ports() para escanear los puertos más comunes (los que están en la lista puertos_comunes, como 22, 80, 443, etc.)
