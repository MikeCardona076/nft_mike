import os
import subprocess
import re
from collections import defaultdict
import time

# Función para verificar si existe la tabla y la cadena
def check_table_and_chain():
    # Verificar si la tabla blacklist existe
    result = subprocess.run(['sudo', 'nft', 'list', 'table', 'ip', 'blacklist'], capture_output=True, text=True)
    table_exists = 'table ip blacklist' in result.stdout

    # Verificar si la cadena input existe dentro de la tabla blacklist
    result = subprocess.run(['sudo', 'nft', 'list', 'chain', 'ip', 'blacklist', 'input'], capture_output=True, text=True)
    chain_exists = 'chain input' in result.stdout

    return table_exists, chain_exists

# Función para crear la tabla y la cadena si no existen
def create_table_and_chain():
    subprocess.run(['sudo', 'nft', 'add', 'table', 'ip', 'blacklist'])
    subprocess.run(['sudo', 'nft', 'add', 'chain', 'ip', 'blacklist', 'input', '{', 'type', 'filter', 'hook', 'input', 'priority', '0', ';', '}'])

# Función para leer los eventos del archivo auth.log
def read_auth_log():
    with open('/var/log/auth.log', 'r') as f:
        for line in f:
            yield line.strip()

# Función para analizar eventos de inicio de sesión fallidos
def parse_auth_log(lines):
    for line in lines:
        if 'Failed password' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                yield ip_address

# Función para verificar si una dirección IP está bloqueada
def is_ip_blocked(ip_address):
    result = subprocess.run(['sudo', 'nft', 'list', 'table', 'ip', 'blacklist'], capture_output=True, text=True)
    return ip_address in result.stdout

# Función para bloquear una dirección IP con NFTables
def block_ip(ip_address):
    subprocess.run(['sudo', 'nft', 'add', 'rule', 'ip', 'blacklist', 'input', 'ip', 'saddr', ip_address, 'drop'])
    print(f'Dirección IP bloqueada: {ip_address}')

# Diccionario para llevar el conteo de intentos fallidos por IP
failed_login_attempts = defaultdict(int)

# Umbral para bloquear una dirección IP
threshold = 3

# Obtener el ID del proceso actual
current_process_id = os.getpid()
print(f"Proceso actual: {current_process_id}")

# Mensaje de inicio del programa
print("El programa está en ejecución...")

# Verificar si la tabla y la cadena existen
table_exists, chain_exists = check_table_and_chain()

# Si no existen, crearlas
if not table_exists or not chain_exists:
    print("Creando la tabla y la cadena...")
    create_table_and_chain()

while True:
    # Leer eventos del archivo auth.log
    lines = read_auth_log()

    # Variable para verificar si se bloquearon todas las direcciones IP
    all_ips_blocked = True

    # Analizar eventos de inicio de sesión fallidos
    for ip_address in parse_auth_log(lines):
        # Verificar si la dirección IP ya está bloqueada
        if not is_ip_blocked(ip_address):
            # Incrementar el contador de intentos fallidos para esta dirección IP
            failed_login_attempts[ip_address] += 1

            # Si se alcanza el umbral, bloquear la dirección IP
            if failed_login_attempts[ip_address] >= threshold:
                block_ip(ip_address)
        else:
            # Si una dirección IP ya está bloqueada, establecer la bandera a False
            all_ips_blocked = False

    # Si todas las direcciones IP están bloqueadas, salir del bucle
    if all_ips_blocked:
        print("Todas las direcciones IP están bloqueadas. Terminando el programa.")
        break

    # Dormir durante un período de tiempo antes de volver a leer el archivo auth.log
    time.sleep(10)  # Puedes ajustar el período de tiempo según tus necesidades
