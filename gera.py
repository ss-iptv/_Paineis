import os
import random
from faker import Faker

# Especificar o caminho do arquivo e a quantidade de linhas desejada
caminho_arquivo = os.path.join('combo', 'usuarios_senhas.txt')
num_linhas = 100000  # Altere este valor para a quantidade de linhas desejada

# Criar instâncias do Faker para pt_PT e pt_BR
faker_pt = Faker('pt_PT')
faker_br = Faker('pt_BR')

def gerar_senha_com_ano(nome, ano, maiuscula=True):
    """Gera uma senha com base no nome e no ano, com a opção de iniciar com letra maiúscula ou minúscula."""
    if maiuscula:
        return f"{nome.capitalize()}{ano}"
    else:
        return f"{nome.lower()}{ano}"

def gerar_usuario_senha(num_usuarios=50000):
    usuarios_senhas = []
    senhas_comuns_br = ["123456", "senha", "123456789", "12345678", "12345", "123123", "qwerty", "abc123", "654321", "123321"]
    
    # Adicionar o usuário nazario123 com senhas comuns
    usuario_nazario = "nazario123"
    for senha in senhas_comuns_br:
        usuarios_senhas.append(f"{usuario_nazario}:{senha}")
    
    for _ in range(num_usuarios):
        # Alternar entre nomes pt_PT e pt_BR e garantir que tenham pelo menos 6 caracteres
        while True:
            nome = random.choice([faker_pt.first_name(), faker_br.first_name()])
            if len(nome.split()[0]) >= 6:  # Usar apenas o primeiro nome e garantir que tenha pelo menos 6 caracteres
                nome = nome.split()[0]
                break
        numero = random.randint(0, 99)
        usuario_com_numero = f"{nome}{numero:02d}"
        usuario_sem_numero = nome
        anos = [2022, 2023, 2024]

        for ano in anos:
            senha_maiuscula = gerar_senha_com_ano(nome, ano, maiuscula=True)
            senha_minuscula = gerar_senha_com_ano(nome, ano, maiuscula=False)
            usuario_ano = f"{nome}{ano}"
        
            usuarios_senhas.append(f"{usuario_ano}:{senha_minuscula}")
            usuarios_senhas.append(f"{usuario_ano}:{senha_maiuscula}")
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
            usuarios_senhas.append(f"{usuario_com_numero}:{senha}")
            usuarios_senhas.append(f"{usuario_sem_numero}:{senha}")  # Adiciona o nome sem números
    return usuarios_senhas

# Função para gerar e salvar usuários e senhas em um arquivo
def salvar_usuarios_senhas(caminho_arquivo, num_linhas):
    # Criar a pasta 'combo' se não existir
    os.makedirs(os.path.dirname(caminho_arquivo), exist_ok=True)
    with open(caminho_arquivo, 'w') as file:
        usuarios_senhas = gerar_usuario_senha(num_linhas)
        file.write('\n'.join(usuarios_senhas) + '\n')
    print(f"Arquivo salvo em {caminho_arquivo}")

# Salvar os usuários e senhas no arquivo especificado
salvar_usuarios_senhas(caminho_arquivo, num_linhas)
