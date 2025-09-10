import socket
import threading
import hashlib
import os
import sys # Importado para usar sys.exit() ou os._exit()

# --- Configurações do Cliente ---
BUFFER_SIZE = 4096
RECEIVED_FILES_DIR = 'received_files'

# Variável para controlar o estado da conexão
connected = False # Definida no escopo global

# --- Funções Auxiliares ---

def calculate_sha256(filepath):
    """Calcula o hash SHA256 de um arquivo."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_message(sock, message):
    """Envia uma mensagem formatada pelo protocolo."""
    global connected
    try:
        sock.sendall(message.encode('utf-8'))
        return True
    except socket.error as e:
        print(f"Erro ao enviar mensagem: {e}")
        connected = False 
        return False
    except Exception as e:
        print(f"Erro inesperado ao enviar mensagem: {e}")
        connected = False 
        return False

def receive_message(sock):

    try:
        header_buffer = b''
        while b'|' not in header_buffer:
            chunk = sock.recv(1)
            if not chunk: # Conexão fechada pelo outro lado
                return None
            header_buffer += chunk

        remaining_header_part = b''
        while header_buffer.count(b'|') < 2:
            chunk = sock.recv(1)
            if not chunk: return None
            header_buffer += chunk
            if len(header_buffer) > 100: # Limite para evitar loop infinito em caso de cabeçalho malformado
                print("Erro: Cabeçalho muito longo ou malformado.")
                return None

        full_header_str = header_buffer.decode('utf-8')
        parts = full_header_str.split('|', 2) 

        if len(parts) < 2:
            print(f"Erro de protocolo: cabeçalho incompleto ou malformado: '{full_header_str}'")
            return None

        command = parts[0]
        try:
            data_size = int(parts[1])
        except ValueError:
            print(f"Erro de protocolo: tamanho de dados inválido: '{parts[1]}'")
            return None

        data_buffer = b''
        bytes_received = 0
        while bytes_received < data_size:
            remaining_bytes = data_size - bytes_received
            chunk = sock.recv(min(remaining_bytes, BUFFER_SIZE))
            if not chunk: return None # Conexão fechada
            data_buffer += chunk
            bytes_received += len(chunk)
        
        return command, data_buffer.decode('utf-8')
    except socket.timeout:
        raise # Relança o timeout para ser capturado no handle_client/receive_server_responses
    except socket.error as e:
        print(f"Erro de socket em receive_message: {e}")
        return None
    except Exception as e:
        print(f"Erro inesperado em receive_message: {e}")
        return None

def receive_server_responses(sock):
    """Thread para receber e processar respostas do servidor."""
    global connected
    while connected: # Loop enquanto a conexão estiver ativa
        try:
            sock.settimeout(0.5) # Pequeno timeout para não bloquear indefinidamente
            response = receive_message(sock) # Esta função não lança mais socket.timeout
            
            if response is None:
                # receive_message retorna None se a conexão foi fechada pelo outro lado
                print("\nConexão com o servidor perdida. Encerrando cliente...")
                connected = False # Atribuição, precisa de global
                break # Sai do loop da thread de recebimento
            
            command, data = response
            
            if command == "ARQUIVO_OK":
                try:
                    # Formato: nome|tamanho|hash
                    metadata_parts = data.split('|', 2)
                    if len(metadata_parts) < 3:
                        print("Erro: Metadados do arquivo incompletos.")
                        continue
                    
                    filename = metadata_parts[0]
                    file_size = int(metadata_parts[1])
                    server_hash = metadata_parts[2]
                    
                    received_filepath = os.path.join(RECEIVED_FILES_DIR, filename)
                    os.makedirs(RECEIVED_FILES_DIR, exist_ok=True)
                    
                    print(f"\nRecebendo arquivo: '{filename}' ({file_size} bytes)...")
                    bytes_received = 0
                    
                    # Para receber o corpo do arquivo, precisamos ler diretamente do socket
                    # sem o receive_message, pois ele espera o protocolo de cabeçalho
                    with open(received_filepath, "wb") as f:
                        while bytes_received < file_size:
                            remaining_bytes = file_size - bytes_received
                            bytes_to_read = min(remaining_bytes, BUFFER_SIZE)
                            file_chunk = sock.recv(bytes_to_read)
                            if not file_chunk:
                                print("Erro: Conexão interrompida durante a transferência do arquivo.")
                                connected = False # Atribuição, precisa de global
                                break
                            f.write(file_chunk)
                            bytes_received += len(file_chunk)
                            # Imprime na mesma linha, depois volta o cursor
                            print(f"\rProgresso: {bytes_received}/{file_size} bytes ({(bytes_received/file_size)*100:.2f}%)", end="")
                    
                    if connected: # Se a conexão ainda estiver ativa após o download
                        print("\nArquivo recebido com sucesso!")
                        # Verificar integridade
                        local_hash = calculate_sha256(received_filepath)
                        print(f"Hash SHA256 do servidor: {server_hash}")
                        print(f"Hash SHA256 local: {local_hash}")
                        if local_hash == server_hash:
                            print("Integridade do arquivo verificada: OK.")
                        else:
                            print("ATENÇÃO: Integridade do arquivo comprometida! Hash não coincide.")
                        print("> ", end="") # Reposiciona o prompt de input
                    
                except Exception as e:
                    print(f"\nErro ao receber arquivo: {e}")
                    print("> ", end="") # Reposiciona o prompt de input
            elif command == "ERRO":
                print(f"\nErro do Servidor: {data}")
                print("> ", end="") # Reposiciona o prompt de input
            elif command == "CHAT_MSG_SERVER":
                print(f"\r[CHAT] {data}\n> ", end="") # Adiciona \n> para reposicionar o prompt de input
                sys.stdout.flush() # Garante que o prompt é redesenhado
            else:
                print(f"\nComando desconhecido do servidor: {command} - {data}")
                print("> ", end="") # Reposiciona o prompt de input
        except socket.timeout:
            # Isso é esperado quando não há dados no momento. A thread continua.
            pass
        except socket.error as e: # Captura erros de socket que não são timeouts
            print(f"\nErro de socket na thread de resposta do cliente: {e}. Conexão perdida.")
            connected = False # Atribuição, precisa de global
            break
        except Exception as e:
            print(f"\nErro inesperado na thread de resposta do cliente: {e}.")
            connected = False # Atribuição, precisa de global
            break

    # Se a thread de recebimento terminar, significa que a conexão caiu
    # Tenta sair do programa principal do cliente também.
    os._exit(1) # Força a saída em caso de desconexão da thread de recebimento


def start_client():
    """Inicializa o cliente TCP."""
    global connected
    server_ip = input("Digite o IP do servidor (padrão: 127.0.0.1): ") or '127.0.0.1'
    server_port = int(input("Digite a porta do servidor (padrão: 12345): ") or 12345)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((server_ip, server_port))
        connected = True # Atribuição, precisa de global
        print(f"Conectado ao servidor em {server_ip}:{server_port}")
    except socket.error as e:
        print(f"Não foi possível conectar ao servidor: {e}")
        return

    # Thread para receber respostas do servidor
    response_thread = threading.Thread(target=receive_server_responses, args=(client_socket,), daemon=True)
    response_thread.start()

    print("\n--- Comandos Disponíveis ---")
    print("SAIR                          - Desconecta do servidor.")
    print("ARQUIVO <nome_do_arquivo.ext> - Solicita um arquivo do servidor.")
    print("CHAT <sua_mensagem>           - Envia uma mensagem para o chat.")
    print("----------------------------\n")
    
    # Cria o diretório de arquivos recebidos se não existir
    os.makedirs(RECEIVED_FILES_DIR, exist_ok=True)

    try:
        while connected: # Loop principal enquanto a conexão estiver ativa
            user_input = input("> ")
            if not connected: # Verifica novamente caso a conexão caia enquanto o input espera
                break
            
            parts = user_input.split(' ', 1)
            command = parts[0].upper()
            
            if command == "SAIR":
                if send_message(client_socket, "SAIR|0|"):
                    print("Solicitação de saída enviada.")
                    connected = False # Atribuição, precisa de global
                break # Sai do loop
            elif command == "ARQUIVO":
                if len(parts) > 1:
                    filename = parts[1]
                    message = f"ARQUIVO_REQ|{len(filename)}|{filename}"
                    send_message(client_socket, message)
                else:
                    print("Uso: ARQUIVO <nome_do_arquivo.ext>")
            elif command == "CHAT":
                if len(parts) > 1:
                    chat_message = parts[1]
                    message = f"CHAT_MSG|{len(chat_message)}|{chat_message}"
                    send_message(client_socket, message)
                else:
                    print("Uso: CHAT <sua_mensagem>")
            else:
                print("Comando inválido. Use SAIR, ARQUIVO ou CHAT.")
                
            # Pequena pausa pode ser removida ou mantida dependendo do desempenho
            # time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nCliente encerrado por interrupção do teclado.")
        connected = False # Atribuição, precisa de global
    except EOFError: # Ctrl+D ou Ctrl+Z
        print("\nEntrada do cliente encerrada.")
        connected = False # Atribuição, precisa de global
    except Exception as e:
        print(f"Erro no loop principal do cliente: {e}")
        connected = False # Atribuição, precisa de global
    finally:
        client_socket.close()
        print("Conexão com o servidor fechada.")
        sys.exit(0) # Termina o programa do cliente de forma limpa

if __name__ == "__main__":
    start_client()