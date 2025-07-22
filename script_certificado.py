# -*- coding: utf-8 -*-

# -----------------------------------------------------------------------------
# SCRIPT DE CONVERSÃO PFX PARA PEM (AWS ACM)
# -----------------------------------------------------------------------------
# Para checar se o certificado tem ou não cadeia, utilizar o comando abaixo  
# openssl pkcs12 -in seu_arquivo.pfx -nokeys -info
#
# OBJETIVO:
# Este script converte um certificado digital no formato PFX (PKCS#12) para
# os três arquivos de texto no formato PEM, que são necessários para importar
# um certificado no AWS Certificate Manager (ACM).
#
# FUNCIONALIDADES:
# 1. Detecção Automática: Procura por arquivos .pfx na mesma pasta.
# 2. Seleção Interativa: Se mais de um arquivo .pfx for encontrado, o usuário
#    pode escolher qual deles deseja converter.
# 3. Saída Organizada: Cria uma pasta separada para os arquivos PEM gerados,
#    com base no nome do arquivo PFX original.
# 4. Segurança: A senha do PFX é solicitada de forma segura, sem ser exibida
#    na tela.
#
# BIBLIOTECAS NECESSÁRIAS:
# - cryptography: `pip install cryptography`
#
# -----------------------------------------------------------------------------

# --- Importação das Bibliotecas ---

# 'os' é usado para interagir com o sistema operacional, como manipular
# caminhos de arquivos, criar diretórios e listar arquivos.
import os

# 'getpass' é usado para solicitar a senha do usuário de forma segura,
# ou seja, o que é digitado não aparece no terminal.
import getpass

# 'sys' permite interagir com o interpretador Python, usado aqui para
# encerrar o script de forma controlada em caso de erro.
import sys

# Importa os módulos específicos da biblioteca 'cryptography'.
# 'serialization' é usado para converter os objetos de chave/certificado
# para o formato de texto PEM.
# 'pkcs12' é o módulo específico para carregar e "desempacotar"
# arquivos PFX (formato PKCS#12).
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def converter_pfx_para_pem(pfx_path, pfx_password, output_dir):
    """
    Função principal que realiza a conversão de um único arquivo PFX.

    Esta função lê o arquivo PFX, extrai a chave privada, o certificado principal
    e a cadeia de certificados intermediários, e os salva em arquivos .pem separados.

    Argumentos:
        pfx_path (str): O caminho completo para o arquivo .pfx a ser convertido.
        pfx_password (str): A senha do arquivo .pfx.
        output_dir (str): O caminho do diretório onde os arquivos .pem serão salvos.
    """
    print(f"\nIniciando conversão do arquivo: {os.path.basename(pfx_path)}")

    try:
        # Abre o arquivo PFX em modo de leitura binária ('rb').
        # O bloco 'with' garante que o arquivo seja fechado automaticamente no final.
        with open(pfx_path, "rb") as pfx_file:
            pfx_data = pfx_file.read()

        # Esta é a função central da biblioteca 'cryptography' para este processo.
        # Ela carrega o conteúdo binário do PFX e a senha (que deve ser em bytes,
        # por isso o .encode('utf-8')) e retorna três objetos:
        # 1. private_key: A chave privada.
        # 2. certificate: O certificado principal (do seu domínio).
        # 3. additional_certificates: Uma lista com os certificados intermediários.
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pfx_data,
            pfx_password.encode('utf-8')
        )

        # --- Etapa 1: Serializar a Chave Privada ---
        # A chave privada é convertida para o formato PEM.
        # `encoding=serialization.Encoding.PEM`: Formato de saída desejado.
        # `format=serialization.PrivateFormat.PKCS8`: Um formato padrão e moderno para chaves privadas.
        # `encryption_algorithm=serialization.NoEncryption()`: ESSENCIAL! O AWS ACM exige
        # que a chave privada seja importada SEM criptografia (sem senha).
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # --- Etapa 2: Serializar o Certificado Principal ---
        # O certificado principal também é convertido para o formato PEM.
        certificate_pem = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

        # --- Etapa 3: Serializar a Cadeia de Certificados ---
        # Itera sobre cada certificado intermediário na lista `additional_certificates`,
        # converte cada um para PEM e depois junta todos em um único bloco de texto.
        chain_pem_parts = [
            cert.public_bytes(encoding=serialization.Encoding.PEM)
            for cert in additional_certificates
        ]
        certificate_chain_pem = b"".join(chain_pem_parts)

        # --- Etapa 4: Salvar os Arquivos de Saída ---

        # Verifica se o diretório de saída já existe. Se não, cria-o.
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Diretório de saída criado: {output_dir}")

        # Define os nomes dos arquivos de saída dentro do diretório de destino.
        key_path = os.path.join(output_dir, 'private_key.pem')
        cert_path = os.path.join(output_dir, 'certificate.pem')
        chain_path = os.path.join(output_dir, 'certificate_chain.pem')

        # Salva o conteúdo da chave privada no arquivo 'private_key.pem'.
        with open(key_path, "wb") as f:
            f.write(private_key_pem)
        print(f"✅ Chave privada salva em: {key_path}")

        # Salva o conteúdo do certificado principal em 'certificate.pem'.
        with open(cert_path, "wb") as f:
            f.write(certificate_pem)
        print(f"✅ Certificado do servidor salvo em: {cert_path}")

        # Salva a cadeia de certificados apenas se ela não estiver vazia.
        if certificate_chain_pem:
            with open(chain_path, "wb") as f:
                f.write(certificate_chain_pem)
            print(f"✅ Cadeia de certificados salva em: {chain_path}")
        else:
            # Se não houver certificados intermediários, informa o usuário.
            print("⚠️ Nenhuma cadeia de certificados intermediários encontrada no arquivo PFX.")
            # Cria um arquivo vazio para consistência.
            open(chain_path, 'a').close()

        print("\nConversão concluída com sucesso!")

    # --- Tratamento de Erros ---
    except ValueError as e:
        # Um 'ValueError' é comumente lançado pela biblioteca para senhas incorretas.
        if "MAC" in str(e) or "password" in str(e):
            print("\n❌ Erro: Senha do PFX incorreta ou arquivo corrompido.")
        else:
            print(f"\n❌ Ocorreu um erro de valor ao processar o arquivo: {e}")
        sys.exit(1)  # Encerra o script com um código de erro.
    except Exception as e:
        # Captura qualquer outro erro inesperado.
        print(f"\n❌ Ocorreu um erro inesperado: {e}")
        sys.exit(1)


# -----------------------------------------------------------------------------
# PONTO DE ENTRADA DO SCRIPT
# -----------------------------------------------------------------------------
# O bloco `if __name__ == "__main__":` garante que o código abaixo só será
# executado quando o script for rodado diretamente (e não quando for importado
# por outro script).
if __name__ == "__main__":
    # Obtém o caminho absoluto do diretório onde o script está localizado.
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Cria uma lista de todos os arquivos na pasta do script que terminam com '.pfx'
    # (ignorando se é maiúsculo ou minúsculo, ex: .pfx, .PFX).
    pfx_files = [f for f in os.listdir(script_dir) if f.lower().endswith('.pfx')]

    # --- Lógica de Seleção de Arquivo ---

    # Verifica se nenhum arquivo .pfx foi encontrado.
    if len(pfx_files) == 0:
        print("❌ Erro: Nenhum arquivo .pfx encontrado na pasta do script.")
        print("Por favor, coloque seu arquivo .pfx na mesma pasta que este script e tente novamente.")
        sys.exit(1)

    # Se apenas um arquivo foi encontrado, seleciona-o automaticamente.
    elif len(pfx_files) == 1:
        pfx_filename = pfx_files[0]
        print(f"Arquivo PFX encontrado: {pfx_filename}")

    # Se múltiplos arquivos foram encontrados, pede para o usuário escolher.
    else:
        print("Múltiplos arquivos .pfx encontrados. Por favor, escolha qual converter:")
        # Enumera e exibe a lista de arquivos encontrados.
        for i, filename in enumerate(pfx_files):
            print(f"  [{i + 1}] {filename}")

        pfx_filename = None
        # Loop infinito que só será quebrado quando o usuário fizer uma escolha válida.
        while True:
            try:
                # Pede ao usuário para digitar o número correspondente ao arquivo.
                escolha = input("Digite o número do arquivo desejado: ")
                escolha_int = int(escolha)
                # Verifica se o número está dentro do intervalo de opções válidas.
                if 1 <= escolha_int <= len(pfx_files):
                    # Seleciona o nome do arquivo da lista (lembrando que a lista começa em 0).
                    pfx_filename = pfx_files[escolha_int - 1]
                    break  # Sai do loop, pois a escolha foi válida.
                else:
                    print("❌ Opção inválida. Por favor, digite um número da lista.")
            except ValueError:
                # Se o usuário digitar algo que não é um número.
                print("❌ Entrada inválida. Por favor, digite apenas o número.")
            except KeyboardInterrupt:
                 print("\n\nOperação cancelada pelo usuário.")
                 sys.exit(0)


    # --- Continuação do Processo Após a Seleção ---

    # Constrói o caminho completo para o arquivo PFX escolhido.
    pfx_path = os.path.join(script_dir, pfx_filename)

    # Define o nome do diretório de saída, baseado no nome do PFX sem a extensão.
    # ex: 'meudominio.pfx' -> 'meudominio_certs'
    output_dir_name = os.path.splitext(pfx_filename)[0] + "_certs"
    output_dir_path = os.path.join(script_dir, output_dir_name)

    try:
        # Solicita a senha do PFX de forma segura.
        password = getpass.getpass(prompt=f"Digite a senha para '{pfx_filename}': ")
        if not password:
            print("\n❌ Erro: A senha não pode ser vazia.")
        else:
            # Chama a função principal de conversão com todos os parâmetros definidos.
            converter_pfx_para_pem(pfx_path, password, output_dir_path)

    except KeyboardInterrupt:
        # Permite que o usuário cancele a operação (Ctrl+C) de forma limpa.
        print("\n\nOperação cancelada pelo usuário.")
        sys.exit(0)
