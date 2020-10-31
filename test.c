#include "encdec.h"

// Initial dummy test program.

int
main(int argc, char **argv, char **envp) {
  int fd;
  aes_key_t key = {
      .key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
 	      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
 	      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	      
	      }
  };
  gcm_ctx      ctx_client, ctx_server;
  gcm_str      s;
  gcm_str      check;
  int          err;
  char        *plaintext = "[AAD]This is a test.";
  char         outbuf[100]   = {0,};
  char         checkbuf[100] = {0,};
  struct iovec invector[1], outvector[1], checkvector[1];
  
  s.msg_length        = strlen(plaintext);
  s.tag_length        = 16;
  s.aad_length        = 0;
  s.in_iov            = invector;
  s.out_iov           = outvector;
  s.pt_iov            = invector;
  s.ct_iov            = outvector;
  invector->iov_base  = (void *)plaintext;
  invector->iov_len   = s.msg_length + s.aad_length;
  outvector->iov_base = (void *)outbuf;
  outvector->iov_len  = s.msg_length + s.aad_length + GCM_TAG_LEN;

  gcm_initialize(&ctx_client, &key, ROLE_CLIENT);
  gcm_encrypt   (&ctx_client, &s, &err);

  check.msg_length      = s.msg_length;
  check.tag_length      = 16;
  check.aad_length      = s.aad_length;
  check.in_iov          = outvector;
  check.out_iov         = checkvector;
  check.pt_iov          = checkvector;
  check.ct_iov          = outvector;
  checkvector->iov_base = (void *)checkbuf;
  checkvector->iov_len  = s.msg_length + s.aad_length;
  
  memcpy(&check.iv, &s.iv, sizeof(s.iv));
  gcm_initialize(&ctx_server, &key, ROLE_SERVER);
  gcm_decrypt(&ctx_server, &check, &err);
  for(int i=0; i<strlen(plaintext); i++) {
    if (plaintext[i] != checkbuf[i]) {
      printf("Fail. Error = %d\n", err);
      exit(-1);
    }
  }
  printf("Success.\n");
}
