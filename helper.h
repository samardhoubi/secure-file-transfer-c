#ifndef HELPER_H
#define HELPER_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

#define BUF_LEN 1024
#define MAX_FILENAME_LEN 255

typedef unsigned char byte_t;

#define ERROR(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define WARN(msg) perror(msg)

#endif
