// servidor udp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <time.h>

#define CHUNK_SIZE 1024
#define TIMEOUT_SEC 2
#define MAX_RETRIES 3

// calculo md5
void calculate_md5(unsigned char *data, size_t len, unsigned char *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        perror("EVP_MD_CTX_new failed");
        exit(1);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, len) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, NULL) != 1) {
        perror("Erro ao calcular MD5");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    EVP_MD_CTX_free(mdctx);
}

// cosmetico
void log_with_time(const char *msg, int seq) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%02d:%02d:%02d] %s %d\n", t->tm_hour, t->tm_min, t->tm_sec, msg, seq);
}

// envio do chunk
void send_chunk(int sockfd, struct sockaddr_in *client_addr, socklen_t addrlen,
                unsigned char *data, int seq) {
    unsigned char buffer[CHUNK_SIZE + 4 + MD5_DIGEST_LENGTH]; // criacao do buffer
    memcpy(buffer, &seq, 4); //endereco da sequencia
    memcpy(buffer + 4, data, CHUNK_SIZE); //dados do chunk

    unsigned char digest[MD5_DIGEST_LENGTH]; //digestao do md5
    calculate_md5(data, CHUNK_SIZE, digest); //calculo md5
    memcpy(buffer + 4 + CHUNK_SIZE, digest, MD5_DIGEST_LENGTH); //escrita md5

    sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)client_addr, addrlen);//envio do chunk
    log_with_time("[ENVIO] Chunk", seq);
}

void send_file(int sockfd, struct sockaddr_in *client_addr, socklen_t addrlen, const char *filename) {
    FILE *file = fopen(filename, "rb"); //Leitura da file
    if (!file) {
        const char *msg = "ERROR: File not found";
        sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr *)client_addr, addrlen);
        fprintf(stderr, "[ERRO] Arquivo não encontrado: %s\n", filename);
        return;
    }

    //pegar o tamanho da file e dividir em quantos chunks vai ser feito
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);
    int total_chunks = (filesize + CHUNK_SIZE - 1) / CHUNK_SIZE;

    //enviar cada 1 dos chunks
    for (int seq = 0; seq < total_chunks; seq++) {
        unsigned char data[CHUNK_SIZE] = {0};
        fread(data, 1, CHUNK_SIZE, file);

        int retries = 0;
        while (retries < MAX_RETRIES) {
            send_chunk(sockfd, client_addr, addrlen, data, seq);

            //setar o timeout do sistema
            struct timeval timeout = {TIMEOUT_SEC, 0};
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            unsigned char ack_buf[4];
            int n = recvfrom(sockfd, ack_buf, 4, 0, NULL, NULL);
            if (n == 4) {
                int ack_seq;
                memcpy(&ack_seq, ack_buf, 4);
                if (ack_seq == seq) break;
            }
            retries++;
            log_with_time("[RETRANSMISSÃO] Tentativa para o chunk", seq);
        }
    }

    // Mensagem de finalização da transferência
    int end_flag = -1;
    unsigned char end_msg[8 + MD5_DIGEST_LENGTH] = {0};
    memcpy(end_msg, &end_flag, 4);
    memcpy(end_msg + 4, &total_chunks, 4);
    calculate_md5((unsigned char *)"", 0, end_msg + 8);
    sendto(sockfd, end_msg, sizeof(end_msg), 0, (struct sockaddr *)client_addr, addrlen);
    printf("[INFO] Envio do arquivo '%s' concluído. Chunks: %d\n", filename, total_chunks);

    fclose(file);
    // Restaurar socket para modo bloqueante (sem timeout) após envio
    struct timeval no_timeout = {0, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(no_timeout));

}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <porta>\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Erro ao criar socket");
        exit(1);
    }

    struct sockaddr_in serv_addr, client_addr;
    socklen_t addrlen = sizeof(client_addr);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Erro no bind");
        close(sockfd);
        exit(1);
    }

    printf("[INFO] Servidor UDP iniciado na porta %d.\n", port);

    while (1) {
        char buffer[2048] = {0};
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&client_addr, &addrlen);
        if (n < 0) {
            perror("[ERRO] Falha no recvfrom");
            continue;
        }

        buffer[n] = '\0';

        if (strncmp(buffer, "GET /", 5) == 0) {
            char *filename = buffer + 5;
            printf("[INFO] Requisição recebida para: %s\n", filename);
            send_file(sockfd, &client_addr, addrlen, filename);
        } else {
            const char *msg = "ERROR: Comando inválido";
            sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr *)&client_addr, addrlen);
            printf("[ERRO] Comando inválido recebido: %s\n", buffer);
        }
    }

    close(sockfd);
    return 0;
}
