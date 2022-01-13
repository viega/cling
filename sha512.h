#ifndef __SHA512_H__
#define __SHA512_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <linux/if_alg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SHA512_TAG_LENGTH 64

typedef struct {
    int listen_fd;
    int fd;
} sha512_ctx;

typedef struct {
    uint8_t bytes[SHA512_TAG_LENGTH];
} sha512_tag;

bool sha512_initialize(sha512_ctx *);
bool sha512_update(sha512_ctx *, const uint8_t *, size_t, int *);
bool sha512_final(sha512_ctx *, sha512_tag *, int *);
bool sha512(sha512_ctx *, const uint8_t *, size_t, sha512_tag *, int *);
#endif
