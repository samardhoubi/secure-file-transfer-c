#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include <sodium.h>
#include "helper.h"
#include "poet.h"
void client_key_exchange(int sockfd, byte_t key[KEYLEN])
{
    byte_t client_pk[crypto_kx_PUBLICKEYBYTES];
    byte_t client_sk[crypto_kx_SECRETKEYBYTES];
    byte_t server_pk[crypto_kx_PUBLICKEYBYTES];

    byte_t rx[crypto_kx_SESSIONKEYBYTES];
    byte_t tx[crypto_kx_SESSIONKEYBYTES];

    byte_t sig[crypto_sign_BYTES];
    byte_t sign_pk[crypto_sign_PUBLICKEYBYTES];

    crypto_kx_keypair(client_pk, client_sk);

    if (write(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES)
        != crypto_kx_PUBLICKEYBYTES)
        ERROR("write pk");

    if (read(sockfd, server_pk, crypto_kx_PUBLICKEYBYTES)
        != crypto_kx_PUBLICKEYBYTES)
        ERROR("read pk");

    if (read(sockfd, sig, crypto_sign_BYTES)
        != crypto_sign_BYTES)
        ERROR("read signature");

    int fd = open("server.pk", O_RDONLY);
    if (fd < 0)
        ERROR("server.pk");

    if (read(fd, sign_pk, crypto_sign_PUBLICKEYBYTES)
        != crypto_sign_PUBLICKEYBYTES)
        ERROR("read server.pk");

    close(fd);

    if (crypto_sign_verify_detached(sig,
                                    server_pk,
                                    crypto_kx_PUBLICKEYBYTES,
                                    sign_pk) != 0)
    {
        fprintf(stderr, "signature verification failed\n");
        exit(EXIT_FAILURE);
    }

    if (crypto_kx_client_session_keys(rx, tx,
                                      client_pk, client_sk,
                                      server_pk) != 0)
        ERROR("session keys");

    for (int i = 0; i < KEYLEN; i++)
        key[i] = rx[i] ^ tx[i];
}

void usage() {
    fputs("Usage: ./client file\n", stderr);
    exit(EXIT_FAILURE);
}

void send_file(int fd, int sockfd, const char *filename, poet_ctx_t *ctx) {
    byte_t iv[16];
    getrandom(iv, 16, 0);

    byte_t fn_len = strlen(filename);
    int header_len = 16 + 1 + fn_len;

    byte_t *header = malloc(header_len);
    memcpy(header, iv, 16);
    header[16] = fn_len;
    memcpy(header + 17, filename, fn_len);

    process_header(ctx, header, header_len);

    if (write(sockfd, header, header_len) != header_len)
        ERROR("sending header");

    block plain;
    block cipher;
    byte_t final_buf[BLOCKLEN];
    byte_t tag[TAGLEN];
    int final_len = 0;

    while (true) {
        char buf[BUF_LEN];
        int n = read(fd, buf, BUF_LEN);

        if (n < 0)
            ERROR("read");

        if (n == 0)
            break;

        int full_block = n / BLOCKLEN;
        int remaining = n % BLOCKLEN;

        for (int i = 0; i < full_block - (remaining == 0 ? 1 : 0); i++) {
            memcpy(plain, buf + i * BLOCKLEN, BLOCKLEN);
            encrypt_block(ctx, plain, cipher);

            if (write(sockfd, cipher, BLOCKLEN) != BLOCKLEN)
                ERROR("sending ciphertext");
        }

        if (remaining == 0 && full_block > 0) {
            memcpy(final_buf,
                   buf + (full_block - 1) * BLOCKLEN,
                   BLOCKLEN);

            final_len = BLOCKLEN;
        } else if (remaining > 0) {
            memcpy(final_buf,
                   buf + full_block * BLOCKLEN,
                   remaining);

            final_len = remaining;
        }
    }

    byte_t final_cipher[BLOCKLEN];

    encrypt_final(ctx,
                  final_buf,
                  final_len,
                  final_cipher,
                  tag);

    write(sockfd, final_cipher, final_len);
    write(sockfd, tag, TAGLEN);

    free(header);
}

int open_server_connection(const char *ip, const int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        ERROR("socket");

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (struct sockaddr *) &server_addr,
                sizeof(server_addr)) == -1)
        ERROR("connect");

    return sockfd;
}

int main(int args, char *argv[]) {
    if (args != 2)
        usage();

    char *filename = basename(argv[1]);

    if (strlen(filename) > MAX_FILENAME_LEN) {
        fprintf(stderr, "%s: %s\n", filename, strerror(ENAMETOOLONG));
        return ENAMETOOLONG;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        ERROR(argv[1]);

    if (sodium_init() < 0)
        ERROR("sodium_init");

    int sockfd = open_server_connection(SERVER_IP, SERVER_PORT);

    byte_t key[KEYLEN];
    client_key_exchange(sockfd, key);

    poet_ctx_t ctx;
    keysetup(&ctx, key);

    send_file(fd, sockfd, filename, &ctx);

    close(fd);
    close(sockfd);

    return 0;
}
