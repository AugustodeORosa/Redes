import socket
import threading
import os

# --- Configurações do Servidor ---
HOST = '127.0.0.1'  # Endereço IP do servidor (localhost)
PORTA = 8080        # Porta que o servidor vai escutar (maior que 1024)
TAMANHO_BUFFER = 1024 # Tamanho do buffer para receber dados

# Função para lidar com cada conexão de cliente em uma thread separada
def lidar_com_cliente(conexao, endereco):
    print(f"[NOVA CONEXÃO] {endereco} conectado.")

    try:
        # Recebe a requisição do cliente (navegador)
        requisicao_bytes = conexao.recv(TAMANHO_BUFFER)
        requisicao_str = requisicao_bytes.decode('utf-8')

        # Se a requisição estiver vazia, ignora
        if not requisicao_str:
            print(f"[CONEXÃO FECHADA] {endereco} desconectou sem enviar dados.")
            return

        print(f"[{endereco}] Requisição recebida:\n{requisicao_str.splitlines()[0]}")

        # --- Processamento da Requisição HTTP ---
        # Pega a primeira linha da requisição (ex: "GET /index.html HTTP/1.1")
        primeira_linha = requisicao_str.splitlines()[0]
        
        try:
            metodo, caminho, versao_http = primeira_linha.split()
        except ValueError:
            print(f"[{endereco}] Requisição mal formada recebida.")
            return

        # Se o caminho for "/", aponta para "index.html" como padrão
        if caminho == '/':
            caminho = '/index.html'

        # Monta o caminho completo do arquivo solicitado
        caminho_do_arquivo = caminho.strip('/') # Remove a barra inicial

        # --- Lógica para encontrar e servir o arquivo ---
        if os.path.exists(caminho_do_arquivo):
            # O arquivo existe, vamos prepará-lo para envio
            try:
                # Determina o tipo de conteúdo (MIME type) pela extensão do arquivo
                if caminho_do_arquivo.endswith('.html'):
                    content_type = 'text/html; charset=utf-8'
                    # Abre o arquivo em modo texto
                    with open(caminho_do_arquivo, 'r', encoding='utf-8') as f:
                        corpo_resposta = f.read().encode('utf-8')
                elif caminho_do_arquivo.endswith('.jpeg') or caminho_do_arquivo.endswith('.jpg'):
                    content_type = 'image/jpeg'
                    # Abre a imagem em modo binário
                    with open(caminho_do_arquivo, 'rb') as f:
                        corpo_resposta = f.read()
                else:
                    # Tipo de arquivo não suportado
                    raise NotImplementedError("Tipo de arquivo não suportado")

                # Monta a resposta HTTP 200 OK
                resposta = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(corpo_resposta)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode('utf-8') + corpo_resposta
                
                print(f"[{endereco}] Enviando resposta: 200 OK para o arquivo {caminho_do_arquivo}")

            except Exception as e:
                # Erro interno no servidor ao tentar ler o arquivo
                print(f"[ERRO NO SERVIDOR] Erro ao ler o arquivo {caminho_do_arquivo}: {e}")
                corpo_resposta = b"<h1>500 Internal Server Error</h1>"
                resposta = (
                    b"HTTP/1.1 500 Internal Server Error\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 30\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    b"<h1>500 Internal Server Error</h1>"
                )
        else:
            # O arquivo não foi encontrado, monta uma resposta 404 Not Found
            print(f"[{endereco}] Arquivo não encontrado: {caminho_do_arquivo}. Enviando 404 Not Found.")
            corpo_resposta_404 = f"""
            <html>
                <head><title>404 Not Found</title></head>
                <body>
                    <h1>404 Not Found</h1>
                    <p>O recurso solicitado '{caminho}' não foi encontrado neste servidor.</p>
                </body>
            </html>
            """.encode('utf-8')
            
            resposta = (
                f"HTTP/1.1 404 Not Found\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(corpo_resposta_404)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode('utf-8') + corpo_resposta_404
        
        # Envia a resposta completa para o cliente
        conexao.sendall(resposta)

    except Exception as e:
        print(f"[ERRO] Ocorreu um erro ao lidar com {endereco}: {e}")
    finally:
        # Fecha a conexão com o cliente
        print(f"[CONEXÃO FECHADA] {endereco} desconectado.")
        conexao.close()

def iniciar_servidor():
    # Cria o socket TCP/IP (AF_INET para IPv4, SOCK_STREAM para TCP)
    servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Permite que o endereço seja reutilizado rapidamente após fechar o servidor
    servidor_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Vincula o socket ao endereço e porta definidos
        servidor_socket.bind((HOST, PORTA))
        # Começa a escutar por conexões entrantes (com um limite de 5 conexões na fila)
        servidor_socket.listen(5)
        print(f"[*] Servidor escutando em {HOST}:{PORTA}")
        print("[*] Pressione CTRL+C para parar o servidor.")

        # Loop principal para aceitar novas conexões
        while True:
            # Aceita uma nova conexão.
            conexao, endereco = servidor_socket.accept()
            
            # Cria uma nova thread para lidar com o cliente recém-conectado
            thread_cliente = threading.Thread(target=lidar_com_cliente, args=(conexao, endereco))
            thread_cliente.start() # Inicia a thread
            
            # Exibe o número de threads ativas (subtrai 1, que é a thread principal)
            print(f"[THREADS ATIVAS] {threading.active_count() - 1}")

    except KeyboardInterrupt:
        print("\n[*] Servidor sendo desligado.")
    except Exception as e:
        print(f"[ERRO CRÍTICO] Falha ao iniciar o servidor: {e}")
    finally:
        servidor_socket.close()

if __name__ == "__main__":
    iniciar_servidor()