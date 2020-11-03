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

#endif
