#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sodium.h>

static void write_file(const char *name, const unsigned char *data, size_t len, int mode)
{
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0)
    {
        perror(name);
        exit(1);
    }

    if (write(fd, data, len) != (ssize_t)len)
    {
        perror("write");
        close(fd);
        exit(1);
    }

    close(fd);
}

static void generate_keys(unsigned char *pk, unsigned char *sk)
{
    crypto_sign_keypair(pk, sk);
}

int main(void)
{
    if (sodium_init() < 0)
    {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    generate_keys(pk, sk);

    write_file("server.pk", pk, crypto_sign_PUBLICKEYBYTES, 0644);
    write_file("server.sk", sk, crypto_sign_SECRETKEYBYTES, 0600);

    return 0;
}
