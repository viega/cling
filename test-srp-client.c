#include "srp.h"

#include <sys/types.h>
#include <sys/socket.h>

void print_bignum(mp_int *);

static void
internal_print_key(srp_ctx *ctx) {
  int i;
  
  for (i=0;i<16;i++) {
    printf("%02x", ctx->keymatter.bytes[i]);
  }
  printf("\n");
}

void
send_A(srp_ctx *ctx, int fd) {
  size_t size, written;
  char  *s;

  size = mp_ubin_size(&ctx->A);
  s = (char *)malloc(size);

  if (mp_to_ubin(&ctx->A, (uint8_t *)s, size, &written) != MP_OKAY) { exit(-1); }
  printf("size = %d, written = %d\n", size, written);
  written = htonl(written);
  write(fd, &written, 4);
  printf("wrote %d bytes\n", write(fd, s, size));
  printf("      %s\n", build_hex_dump((uint8_t *)s, size));
  printf("\n");
}

void
read_B(srp_ctx *ctx, int fd) {
    uint32_t n, m, size;
  uint8_t *buf, *p;

  // 32 bit length, network byte order.                                                                         
  recv(fd, &n, 4, 0);
  n = htonl(n);
  printf("Going to read %d bytes\n", n);
  size = n;
  buf = (uint8_t *)malloc(n);
  p   = buf;
  while (n) {
    m = read(fd, p, n);
    p += m;
    n -= m;
  }
  printf("      %s\n", build_hex_dump(buf, size));
  printf("\n");

  if (mp_from_ubin(&ctx->B, buf, size) != MP_OKAY) { exit(-1); }
  printf("Read B = ");
  print_bignum(&ctx->B);
  printf("\n");
}

int main() {
  struct sockaddr_in sa = {0,};
  int                fd;
  char               buf[256] = {0,};
  size_t             pwlen;
  srp_ctx            client_ctx;
  sha512_tag         tag;

  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(PORT);
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  fd = socket(AF_INET, SOCK_STREAM, 0);

  printf("Using default username (test)\npassword: ");
  fgets(buf, sizeof(buf), stdin);
  for (pwlen = 0; pwlen < 256; pwlen++) {
    if (buf[pwlen] == '\n') {
      break;
    }
  }

  printf("Connecting.\n");
  srp_init(&client_ctx);
  client_ctx.username = (uint8_t *)"test";
  client_ctx.namelen  = strlen((char *)client_ctx.username);
  client_ctx.salt     = (uint8_t *)"testsalt";
  client_ctx.saltlen  = strlen((char *)client_ctx.salt);

  connect(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  srp_party_1_step_1(&client_ctx);
  printf("Sending A = ");
  print_bignum(&(client_ctx.A));
  printf("\n");
  send_A(&client_ctx, fd);
  read_B(&client_ctx, fd);
  srp_party_1_step_2(&client_ctx, (uint8_t *)buf, pwlen);
  // Send proof.
  write(fd, &client_ctx.proof1.bytes, 64);
  recv(fd, tag.bytes, 64, 0);
  if (!srp_party_1_step_3(&client_ctx, &tag)) {
    printf("Authentication failed.\n");
    return 0;
  }
  printf("Authentication succeeded.\n");
  printf("Key = ");
  internal_print_key(&client_ctx);
  return 0;
}
