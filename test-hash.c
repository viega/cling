#include "sha512.h"

int main(int argc, char **argv) {
  sha512_ctx c;
  sha512_tag t;
  int        err;
  
  char *test = "This is a test string. What is its hash value?\n";
  sha512_initialize(&c);
  sha512(&c, (uint8_t *)test, strlen(test), &t, &err);
  for (int i=0;i<SHA512_TAG_LENGTH;i++) {
    printf("%02x", t.bytes[i]);
  }
  printf("\n");
  sha512_initialize(&c);
  sha512_update(&c, (uint8_t *)test, 10, &err);
  sha512_update(&c, (uint8_t *)&test[10], strlen(test)-10, &err);
  sha512_final(&c, &t, &err);
  for (int i=0;i<SHA512_TAG_LENGTH;i++) {
    printf("%02x", t.bytes[i]);
  }
  printf("\n");
}
