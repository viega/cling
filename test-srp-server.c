#include "srp.h"

#include <sys/types.h>
#include <sys/socket.h>

void print_bignum(mp_int *);

void
load_database() {
  printf("Added user 'test' with password 'testpw'\n");
}

void
read_A(srp_ctx *ctx, int fd) {
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
  
  if (mp_from_ubin(&ctx->A, buf, size) != MP_OKAY) { exit(-1); }
  printf("Read A = ");
  print_bignum(&ctx->A);
  printf("\n");
}

// Theoretically should send the sale too, but hard coding it for the moment.
void
send_B(srp_ctx *ctx, int fd) {
  size_t size, written;
  char  *s;

  size = mp_ubin_size(&ctx->B);
  s = (char *)malloc(size);

  if (mp_to_ubin(&ctx->B, (uint8_t *)s, size, &written) != MP_OKAY) { exit(-1); }
  printf("size = %d, written = %d\n", size, written);
  written = htonl(written);
  write(fd, &written, 4);
  printf("wrote %d bytes\n", write(fd, s, size));
  printf("      %s\n", build_hex_dump((uint8_t *)s, size));
  printf("\n");
}

void
read_proof(sha512_tag *tag, int fd) {
  recv(fd, tag->bytes, 64, 0);
}

static void
internal_print_key(srp_ctx *ctx) {
  int i;
  
  for (i=0;i<16;i++) {
    printf("%02x", ctx->keymatter.bytes[i]);
  }
  printf("\n");
}

void
do_handshake(int fd) {
  srp_ctx    server_ctx;
  char      *pw = "testpw";
  sha512_tag client_proof;

  srp_init(&server_ctx);
  server_ctx.username = (uint8_t *)"test";
  server_ctx.namelen  = strlen((char *)server_ctx.username);
  server_ctx.salt     = (uint8_t *)"testsalt";
  server_ctx.saltlen  = strlen((char *)server_ctx.salt);

  srp_compute_v(&server_ctx, (uint8_t *)pw, strlen(pw));

  printf("Reading A.\n");
  read_A(&server_ctx, fd);
  printf("Done.\n");
  srp_party_2_step_1(&server_ctx);
  printf("Step 1 done; sending B.\n");
  send_B(&server_ctx, fd);
  printf("Reading proof.\n");
  read_proof(&client_proof, fd);
  if (!srp_party_2_step_2(&server_ctx, &client_proof)) {
    printf("Authentication failed.\n");
    return;
  }
  printf("Authentication succeeded. Sending our proof.\n");
  write(fd, &server_ctx.proof2.bytes, 64);
  printf("Key = ");
  internal_print_key(&server_ctx);
}

int
main() {
  int fd;
  int ss = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sa = {0,}, remote;
  socklen_t remotelen;

  
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(PORT);
  sa.sin_addr.s_addr = INADDR_ANY;

  load_database();

  setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  if (bind(ss, (struct sockaddr *)&sa, sizeof(sa))) { goto fail; }
  if (setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))) { goto fail; }
  if (listen(ss, 10)) { goto fail; }
  printf("Listening on 0.0.0.0 port 7890.\n");
  fd = accept(ss, (struct sockaddr *)&remote, &remotelen);
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))  ;
  if (fd == -1) { goto fail; }
  printf("Accepted fd %d.\n", fd);
  do_handshake(fd);
  close(fd);
  close(ss);
  return 0;
  
 fail:
  perror("ugh");
}
