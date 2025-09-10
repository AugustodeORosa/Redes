// cliente udp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#define CHUNK_SIZE 1024
#define LOSS_PROBABILITY 20  // 20% de chance de perder pacote
#define DELAY_MS 100          // Delay de 100ms simulado

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

void delay(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

int simulate_loss() {
    return (rand() % 100) < LOSS_PROBABILITY;
}

void log_info(const char *msg, int seq) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%02d:%02d:%02d] %s %d\n", t->tm_hour, t->tm_min, t->tm_sec, msg, seq);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <ip_servidor> <porta> <arquivo_requisitado>\n", argv[0]);
        exit(1);
    }

    srand(time(NULL));

    int sockfd;
    struct sockaddr_in serv_addr;
    socklen_t addrlen = sizeof(serv_addr);
    char buffer[2048];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Erro ao criar socket");
        exit(1);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &serv_addr.sin_addr);

    char request[256];
    sprintf(request, "GET /%s", argv[3]);
    sendto(sockfd, request, strlen(request), 0, (struct sockaddr *)&serv_addr, addrlen);

    FILE *out = fopen(argv[3], "wb");
    if (!out) {
        perror("Erro ao abrir arquivo para escrita");
        exit(1);
    }

    int expected_seq = 0;

    while (1) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n < 0) {
            perror("[ERRO] Falha no recvfrom");
            continue;
        }

        int seq;
        memcpy(&seq, buffer, 4);

        if (seq == -1) {
            int total_chunks;
            memcpy(&total_chunks, buffer + 4, 4);
            printf("[INFO] Transferência completa. Total de chunks: %d\n", total_chunks);
            break;
        }

        unsigned char *data = (unsigned char *)(buffer + 4);
        unsigned char *received_md5 = data + CHUNK_SIZE;

        unsigned char calc_md5[MD5_DIGEST_LENGTH];
        calculate_md5(data, CHUNK_SIZE, calc_md5);

        if (memcmp(received_md5, calc_md5, MD5_DIGEST_LENGTH) != 0) {
            log_info("[ERRO] Checksum inválido no chunk", seq);
            continue;
        }

        if (seq != expected_seq) {
            log_info("[AVISO] Chunk fora de ordem. Esperado", expected_seq);
            continue;
        }

        if (simulate_loss()) {
            log_info("[SIMULADO] Perda do ACK do chunk", seq);
        } else {
            sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&serv_addr, addrlen);
        }

        fwrite(data, 1, CHUNK_SIZE, out);
        expected_seq++;
        delay(DELAY_MS);
    }

    fclose(out);
    close(sockfd);
    printf("[SUCESSO] Arquivo salvo como '%s'\n", argv[3]);
    return 0;
}
