import socket
import threading
import hashlib
import os
import time
import queue # Para comunicação entre threads

# --- Configurações do Servidor ---
HOST = '0.0.0.0'  # Endereço IP local (0.0.0.0 para escutar em todas as interfaces)
PORT = 12345        # Porta para escutar conexões (maior que 1024)
BUFFER_SIZE = 4096  # Tamanho do buffer para envio/recebimento de dados
FILE_DIR = 'files_to_send' # Diretório onde os arquivos estão localizados

# Lista para armazenar as threads de clientes e seus sockets (para chat global)
client_threads = []
client_sockets = []
client_locks = {} # Para garantir que apenas uma thread envie para um socket por vez

# Fila para mensagens de chat do servidor para os clientes
server_chat_queue = queue.Queue()

# --- Funções Auxiliares ---

def calculate_sha256(filepath):
   
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Lê o arquivo em blocos para lidar com arquivos grandes
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_message(conn, message):
    
    try:
        conn.sendall(message.encode('utf-8'))
    except socket.error as e:
        print(f"Erro ao enviar mensagem: {e}")
        return False
    return True

def receive_message(conn):
   
    try:
        header_buffer = b''
        while b'|' not in header_buffer:
            chunk = conn.recv(1) 
            if not chunk: # Conexão fechada pelo outro lado
                return None 
            header_buffer += chunk

    
        remaining_header_part = b''
        while header_buffer.count(b'|') < 2:
            chunk = conn.recv(1)
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
            chunk = conn.recv(min(remaining_bytes, BUFFER_SIZE))
            if not chunk: return None # Conexão fechada
            data_buffer += chunk
            bytes_received += len(chunk)
        
        return command, data_buffer.decode('utf-8') 
    except socket.timeout: 
        raise 
    except socket.error as e:
        print(f"Erro de socket em receive_message: {e}")
        return None
    except Exception as e:
        print(f"Erro inesperado em receive_message: {e}")
        return None

def handle_client(conn, addr, client_id):
    print(f"[Cliente {client_id}] Conectado de {addr}")
    client_sockets.append(conn) # Adiciona o socket à lista global
    client_locks[conn] = threading.Lock() # Cria um lock para este cliente

    try:
        while True:
            # Verifica se há mensagens do servidor para enviar
            if not server_chat_queue.empty():
                try:
                    chat_msg = server_chat_queue.get_nowait()
                    # Percorre uma cópia da lista de sockets para evitar problemas se a lista for modificada durante o loop
                    for client_sock in list(client_sockets): 
                
                        if client_sock in client_locks: 
                             with client_locks[client_sock]: 
                                 if not send_message(client_sock, f"CHAT_MSG_SERVER|{len(chat_msg)}|{chat_msg}"):
                                     print(f"Aviso: Falha ao enviar chat do servidor para {client_sock.getpeername()}.")
                    server_chat_queue.task_done()
                except queue.Empty:
                    pass # Fila estava vazia, mas outro thread a esvaziou
                except Exception as e:
                    print(f"Erro ao enviar mensagem do servidor para clientes no chat: {e}")


            conn.settimeout(0.5) # Pequeno timeout para não bloquear eternamente na leitura

            try:
                request = receive_message(conn) 
                
                if request is None: 
                    print(f"[Cliente {client_id}] Cliente {addr} desconectou (conexão fechada).")
                    break 
                
                command, data = request
                print(f"[Cliente {client_id}] Recebido: Comando='{command}', Dados='{data}'")

                if command == "SAIR":
                    print(f"[Cliente {client_id}] Cliente {addr} solicitou sair.")
                    break 
                elif command == "ARQUIVO_REQ":
                    filename = data
                    filepath = os.path.join(FILE_DIR, filename)
                    if os.path.exists(filepath) and os.path.isfile(filepath):
                        file_size = os.path.getsize(filepath)
                        file_hash = calculate_sha256(filepath)
                        
                        metadata = f"{filename}|{file_size}|{file_hash}"
                        response_header = f"ARQUIVO_OK|{len(metadata)}|{metadata}"
                        
                        with client_locks[conn]: 
                            send_message(conn, response_header)
                            
                            with open(filepath, "rb") as f:
                                while True:
                                    bytes_read = f.read(BUFFER_SIZE)
                                    if not bytes_read:
                                        break # Fim do arquivo
                                    conn.sendall(bytes_read)
                            print(f"[Cliente {client_id}] Arquivo '{filename}' enviado para {addr}.")
                    else:
                        error_msg = "Arquivo nao encontrado."
                        response = f"ERRO|{len(error_msg)}|{error_msg}"
                        with client_locks[conn]:
                            send_message(conn, response)
                        print(f"[Cliente {client_id}] Arquivo '{filename}' nao encontrado.")
                elif command == "CHAT_MSG":
                    message = data
                    print(f"[Cliente {client_id}] Chat de {addr}: {message}")
                    for client_sock in client_sockets:
                        if client_sock != conn and client_sock in client_locks:
                            with client_locks[client_sock]:
                                send_message(client_sock, f"CHAT_MSG_SERVER|{len(f'{addr[0]}:{addr[1]}: {message}')}|{addr[0]}:{addr[1]}: {message}")
                else:
                    error_msg = "Comando desconhecido."
                    response = f"ERRO|{len(error_msg)}|{error_msg}"
                    with client_locks[conn]:
                        send_message(conn, response)
            except socket.timeout:
                pass
            except socket.error as e: 
                print(f"[Cliente {client_id}] Erro de socket na thread do cliente {addr}: {e}. Conexão perdida.")
                break 
            except Exception as e:
                print(f"[Cliente {client_id}] Erro inesperado na thread do cliente {addr}: {e}")
                break 
    finally:
        if conn in client_sockets:
            client_sockets.remove(conn)
        if conn in client_locks:
            del client_locks[conn]
        conn.close()
        print(f"[Cliente {client_id}] Conexão com {addr} encerrada.")


def server_chat_input():
    while True:
        try:
            message = input("Servidor (para todos): ")
            if message.lower() == 'sair':
                break 
            server_chat_queue.put(f"Servidor: {message}")
        except EOFError: # Ctrl+D ou Ctrl+Z
            print("\nEntrada do servidor encerrada.")
            break
        except Exception as e:
            print(f"Erro na entrada do servidor: {e}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Reusa o endereço
    server_socket.bind((HOST, PORT))
    server_socket.listen(5) # Aceita até 5 conexões pendentes
    print(f"Servidor escutando em {HOST}:{PORT}")

    # Cria o diretório de arquivos se não existir
    os.makedirs(FILE_DIR, exist_ok=True)

    # Thread para entrada de chat do servidor
    chat_input_thread = threading.Thread(target=server_chat_input, daemon=True)
    chat_input_thread.start()

    client_id_counter = 0
    try:
        while True:
            conn, addr = server_socket.accept()
            client_id_counter += 1
            # Passa o socket diretamente para o args para a thread
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, client_id_counter), daemon=True)
            client_threads.append(client_thread)
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServidor encerrado por interrupção do teclado.")
    finally:
        for t in client_threads:
            pass
        server_socket.close()
        print("Socket do servidor fechado.")

if __name__ == "__main__":
    start_server()