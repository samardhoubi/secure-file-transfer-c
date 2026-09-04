#include <arpa/inet.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "poet.h"
#include "helper.h"
#include <sodium.h>
void server_key_exchange(int sockfd, byte_t session_key[])
{
    byte_t server_pk[crypto_kx_PUBLICKEYBYTES];
    byte_t server_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(server_pk, server_sk);
    byte_t client_pk[crypto_kx_PUBLICKEYBYTES];
    if (read(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES)
    {
        WARN("receiving public key");
        return;
    }
    unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
    int fd = open("server.sk", O_RDONLY);
    if (fd < 0)
    {
        WARN("server.sk");
        return;
    }

    if (read(fd, sign_sk, crypto_sign_SECRETKEYBYTES)
            != crypto_sign_SECRETKEYBYTES)
    {
        WARN("reading server.sk");
        close(fd);
        return;
    }
    close(fd);
    unsigned char sig[crypto_sign_BYTES];

    crypto_sign_detached(
        sig,
        NULL,
        server_pk,
        crypto_kx_PUBLICKEYBYTES,
        sign_sk);
    if (write(sockfd, server_pk, crypto_kx_PUBLICKEYBYTES)!= crypto_kx_PUBLICKEYBYTES)
    {
        WARN("sending public key");
        return;
    }
    if (write(sockfd, sig,
              crypto_sign_BYTES)
            != crypto_sign_BYTES)
    {
        WARN("sending signature");
        return;
    }
    byte_t rx[crypto_kx_SESSIONKEYBYTES];
    byte_t tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_server_session_keys(
                rx,
                tx,
                server_pk,
                server_sk,
                client_pk) != 0)
    {
        ERROR("server session keys");
        return;
    }
    for (int i = 0; i < crypto_kx_SESSIONKEYBYTES; i++)
    {
        session_key[i] = tx[i] ^ rx[i];
    }
}
void write_file(int sockfd) {
    byte_t session_key[crypto_kx_SESSIONKEYBYTES];
    server_key_exchange(sockfd, session_key);
    poet_ctx_t ctx;
    keysetup(&ctx, session_key);
    byte_t iv[16];
    byte_t fn_len;
    read(sockfd, iv, 16);
    read(sockfd, &fn_len, 1);
    char filename[BUF_LEN];
    read(sockfd, filename, fn_len);
    filename[fn_len] = '\0';
    char enc_name[BUF_LEN];
    strcpy(enc_name, filename);
    strcat(enc_name, ".enc");
    int fd = open(enc_name,O_CREAT | O_WRONLY | O_EXCL,0664);
    if (fd < 0) {
        WARN(enc_name);
        return;
    }
    write(fd, iv, 16);
    int n;
    char buf[BUF_LEN];
    while (true) {
        n = read(sockfd, buf, BUF_LEN);
        if (n <= 0)
            break;

        if (write(fd, buf, n) != n) {
            WARN("writing file content failed");
            break;
        }
    }

    close(fd);
    int header_len = 16 + 1 + fn_len;
    byte_t *header = malloc(header_len);
    memcpy(header, iv, 16);
    header[16] = fn_len;
    memcpy(header + 17, filename, fn_len);
    process_header(&ctx, header, header_len);
    byte_t final_cipher[BLOCKLEN];
    byte_t final_plain[BLOCKLEN];
    byte_t tag[TAGLEN];
    int enc_fd = open(enc_name, O_RDONLY);
    lseek(enc_fd, 16, SEEK_SET);
    struct stat st;
    fstat(enc_fd, &st);
    block cipher;
    block plain;
    int out_fd = open(filename,O_CREAT | O_WRONLY | O_TRUNC,0664);
    off_t enc_size = st.st_size;
    int final_len;
    off_t ciphertext_len = enc_size - 16 - TAGLEN;
    while (ciphertext_len > BLOCKLEN)
    {
        if (read(enc_fd, cipher, BLOCKLEN) != BLOCKLEN)
        {
            WARN("reading ciphertext block");
            break;
        }

        decrypt_block(&ctx, cipher, plain);

        if (write(out_fd, plain, BLOCKLEN) != BLOCKLEN)
        {
            WARN("writing plaintext block");
            break;
        }

        ciphertext_len -= BLOCKLEN;
    }
    final_len = ciphertext_len;
    read(enc_fd, final_cipher, final_len);
    read(enc_fd, tag, TAGLEN);
    int res = decrypt_final(&ctx,
                            final_cipher,
                            final_len,
                            tag,
                            final_plain);
    if (res != 0)
    {
        WARN("tag verification failed");
        close(out_fd);
        remove(filename);
        free(header);
        close(enc_fd);
        return;
    }
    write(out_fd, final_plain, final_len);
    close(out_fd);
    remove(enc_name);
    free(header);
    close(enc_fd);
}

void *client_handler(void *sockfd) {
    int *socket = sockfd;

    write_file(*socket);

    close(*socket);
    free(sockfd);

    return NULL;
}

int open_server_socket(const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        ERROR("socket");

    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(sockfd, (struct sockaddr *) &server_addr,
             sizeof(struct sockaddr_in)) != 0)
        ERROR("bind");

    if (listen(sockfd, 10) != 0)
        ERROR("listen");

    return sockfd;
}

int main() {
    if (sodium_init() < 0)
        ERROR("sodium_init");
    int sockfd = open_server_socket(SERVER_IP, SERVER_PORT);

    pthread_t t;
    struct sockaddr_in new_addr;

    while (true) {
        socklen_t addr_size = sizeof(new_addr);

        int *sockp = malloc(sizeof(int));
        *sockp = accept(sockfd, (struct sockaddr *) &new_addr, &addr_size);

        if (pthread_create(&t, NULL, client_handler, sockp))
            WARN("pthread_create");

        pthread_detach(t);
    }
}
