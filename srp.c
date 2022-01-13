#include <stdlib.h>
#include <sys/random.h>

#include "srp.h"


static unsigned char trans[256] = {
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '!', '"', '#', '$', '%', '&', '\'',
  '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
  '2', '3', '4', '5', '6', '7', '8', '9', ':', ';',
  '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E',
  'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
  'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c',
  'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
  'x', 'y', 'z', '{', '|', '}', '~', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
  '.', '.', '.', '.', '.', '.'
};

// This is an implementation of SRP-6a, which is now in the public domain.

#define SRP_PRIME_SIZE 2048
#define SRP_TEST_PRIME_SIZE 8
// This 2048-bit prime is represented as an ASCII decimal string.
// It was generated using libtomcrypt's mp_prime_rand().
// In base 10, it is:
// 1843612808402778311968495942859356768591672976950482680651693230080225439128
// 0076787855502251434802362857801484459752833302719937107445723486901760196112
// 2049395778062536395753097820225836340587746737105916631957060056659865001215
// 6523117607076316779078673635650296101375783785602466520712115802374754545869
// 0509393971092854629668853538809986366954047004808035089755792792838021653125
// 6952812011449457844891223152677732603226353256482679504589743847169557247528
// 4695056030090639955213374636889154653821873212849549790868116631872456804739
// 8265285955583376466814924469336968027504068363361346982874722604064289572518
// 187212907

uint8_t test_N[] = {'\x17'};
uint8_t N[] = {
	       '\x92', '\x0A', '\xD1', '\xED', '\xED', '\xC7', '\x17', '\xBA',
	       '\x3B', '\xFE', '\x24', '\xBB', '\xAB', '\xE1', '\x08', '\x37',
	       '\xF3', '\xD7', '\xD2', '\x16', '\x7C', '\xAD', '\x8B', '\x1C',
	       '\x31', '\xFC', '\x39', '\x87', '\x81', '\xD9', '\x39', '\xDB',
	       '\x51', '\x8A', '\xDE', '\xC7', '\x33', '\xC6', '\xA5', '\x97',
	       '\x94', '\x70', '\xA2', '\xF7', '\x91', '\x13', '\x19', '\x0C',
	       '\x31', '\xC5', '\x9F', '\x1D', '\xF5', '\x0F', '\x7D', '\x59',
	       '\x23', '\xB7', '\x30', '\x01', '\x95', '\x93', '\x28', '\x66',
	       '\x0C', '\x90', '\xE1', '\xD7', '\xB0', '\x26', '\x6F', '\xC3',
	       '\x8A', '\x08', '\xA2', '\x93', '\x78', '\xEC', '\xBA', '\x2A',
	       '\xEB', '\x2B', '\x02', '\x72', '\xF4', '\x4B', '\x0F', '\x79',
	       '\x34', '\x7B', '\x9B', '\xFD', '\x0E', '\x87', '\x3E', '\x4D',
	       '\x2D', '\x69', '\xA1', '\xE5', '\xFF', '\x1B', '\x67', '\x1A',
	       '\xA4', '\x59', '\xB7', '\x1D', '\x38', '\x61', '\xE6', '\x3C',
	       '\xAB', '\x8A', '\x97', '\xC6', '\xEE', '\xC8', '\x24', '\xDE',
	       '\x66', '\x9F', '\x64', '\x7B', '\x1F', '\xB7', '\x31', '\xFC',
	       '\x08', '\x53', '\xDA', '\xD2', '\xD0', '\xF8', '\x44', '\x58',
	       '\x80', '\x88', '\x81', '\x0A', '\x2E', '\x19', '\xC8', '\x72',
	       '\x29', '\x1E', '\x23', '\xC5', '\xD3', '\x18', '\x97', '\x9E',
	       '\x39', '\xE0', '\x01', '\x61', '\x68', '\x00', '\xB7', '\x42',
	       '\x44', '\x6E', '\xEA', '\xCB', '\xAF', '\x3E', '\xE1', '\xC8',
	       '\xA2', '\x06', '\x7A', '\xC2', '\x3F', '\x3B', '\xC2', '\xFB',
	       '\x1D', '\x35', '\x05', '\x17', '\xE0', '\x28', '\x55', '\x0E',
	       '\xEC', '\x60', '\x13', '\x78', '\x71', '\xA8', '\x03', '\xF5',
	       '\x9B', '\x97', '\x06', '\x10', '\xEE', '\x3E', '\xCC', '\x26',
	       '\x26', '\x9D', '\x6C', '\x0C', '\x64', '\x7F', '\xBC', '\x5B',
	       '\xDB', '\x5F', '\xF1', '\x55', '\x85', '\xD5', '\x4F', '\x45',
	       '\xD7', '\x56', '\x4D', '\x14', '\xA7', '\x75', '\x9E', '\x31',
	       '\xD0', '\xB9', '\x1B', '\x1A', '\x2C', '\x12', '\xF1', '\x73',
	       '\x22', '\x1B', '\xE2', '\xAE', '\x0B', '\x33', '\xBA', '\x9A',
	       '\xD5', '\x09', '\xF4', '\xE3', '\x88', '\x8C', '\x4F', '\x8E',
	       '\x7C', '\x75', '\x67', '\xB4', '\x87', '\xC3', '\xA0', '\x6B'
};

// This is going to get hashed.
static uint8_t g = 2;

static mp_int     mp_N;
static mp_int     mp_g;
static mp_int     mp_k;
static mp_int     mp_nil; // Used to test if A should be accepted.
static sha512_tag H_N;  
static bool       inited = false;


char *
build_hex_dump(unsigned char *bytes, uint32_t len) {
  char     *ret, *p;
  char      buf[21] = {0,};
  u_int32_t i, j, n;

// Estimate that each byte takes 10 chars to represent for now.  Come back and do the math.
  ret = (char *)malloc(100 * len);
  p   = ret;

  for (i=j=0; i<len; i++) {
    if (i && !(i%4)) {
      if (!(i%16)) {
        n = sprintf(p, "    %s (0x%04x-0x%04x)\n      ",
                    buf,
                    (unsigned int)(i-16),
                    (unsigned int)(i-1));
        p += n;
        memset (buf, 0, 20);
        j = 0;
      } else {
        n = sprintf(p, " ");
        p += n;
        buf[j++] = ' ';
      }
    }
    buf[j++] = trans[(int)(*bytes)];
    n = sprintf(p, "%02x", *bytes++);
    p += n;
  }
  j = i;

  while (j % 16) {
    n = sprintf(p, "  ");
    p += n;
    if (!(j%4)) {
      n = sprintf (p, " ");
      p += n;
    }
    j++;
  }
  n = sprintf(p, "    %s", buf);
  p += n;
  j = i;
  while (j % 16) {
    n = sprintf(p, " ");
    p += n;
    if (!(j%4)) {
      n = sprintf(p, " ");
      p += n;
    }
    j++;
  }
  n = sprintf(p, " (0x%04x-0x%04x)\n", (unsigned char)(((i-1)/16)*16), i-1);
  p += n;
  *p = 0;
  return ret;
}

void
print_bignum(mp_int *n) {
  size_t size, written;
  char  *s;

  if (mp_radix_size(n, 10, &size) != MP_OKAY) { printf("1\n"); exit(-1); }
  s = (char *)malloc(size);

  if (mp_to_radix(n, s, size, &written, 10) != MP_OKAY) { printf("2\n"); exit(-1); }

  printf("%s", s);
  free(s);
}

// k is a hash of N and g, that will then be used as a number in GF(N)
// So we take the hash and convert it to a bignum.

void
srp_compute_k(srp_ctx *ctx) {
  sha512_tag tag;
  int        error;

  // k = H(N, g) (SRP-6a)
  // We hash in the raw byte streams for N and g, not the mp_ints.
  sha512_update(&ctx->hctx, N, sizeof(N), &error);
  sha512_update(&ctx->hctx, &g, sizeof(1), &error);
  sha512_final (&ctx->hctx, &tag, &error);
  if (mp_from_ubin(&mp_k, (const uint8_t *)&tag.bytes, SHA512_TAG_LENGTH) != MP_OKAY) {
    printf("3\n");
    exit(-1);
  }
  if (mp_mod(&mp_k, &mp_N, &mp_k) != MP_OKAY) {     printf("4\n");exit(-1); }
}

void
srp_init(srp_ctx *ctx) {
  int error;
  
  sha512_initialize(&ctx->hctx);
  if (!inited) {
    if (mp_init(&mp_N)    != MP_OKAY)                 { printf("5\n"); exit(-1); }
    if (mp_init(&mp_nil)  != MP_OKAY)                 { printf("6\n"); exit(-1); }
    if (mp_init(&mp_g)    != MP_OKAY)                 { printf("7\n"); exit(-1); }
    if (mp_from_ubin(&mp_N, N, sizeof(N)) != MP_OKAY) { printf("8\n"); exit(-1); }
    mp_set(&mp_nil, 0);
    mp_set(&mp_g,   2);
    srp_compute_k(ctx);
    // Not quite following the suggested proof here.  The one they
    // provide is overkill anyway.
    sha512_update(&ctx->hctx, N,  sizeof(N), &error);
    sha512_final (&ctx->hctx, &H_N, &error);
  }
  ctx->N_ptr    = &mp_N;
  ctx->g_ptr    = &mp_g;
  ctx->k_ptr    = &mp_k;
  ctx->Zero_ptr = &mp_nil;
  if (mp_init(&ctx->u) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->a) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->b) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->A) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->B) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->x) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->v) != MP_OKAY)    { exit(-1); }
  if (mp_init(&ctx->S) != MP_OKAY)    { exit(-1); }  
  ctx->salt     = NULL;
  ctx->username = NULL;
  ctx->saltlen  = 0;
  ctx->namelen  = 0;
}

// TODO: add const
void
srp_compute_x(srp_ctx *ctx, uint8_t *pw, uint32_t pwlen) {
  sha512_tag tag;
  int        error;
  // x = H(s, p) 
  sha512_update     (&ctx->hctx, ctx->salt, ctx->saltlen, &error);
  sha512_update     (&ctx->hctx, pw, pwlen, &error);
  sha512_final      (&ctx->hctx, &tag, &error);
  if (mp_from_ubin(&ctx->x, (const uint8_t *)&tag.bytes, SHA512_TAG_LENGTH) != MP_OKAY) {
    printf("11\n");
    exit(-1);
  }
  if (mp_mod(&ctx->x, ctx->N_ptr, &ctx->x) != MP_OKAY) { printf("12\n"); exit(-1); }
}

void
srp_compute_v(srp_ctx *ctx, uint8_t *pw, uint32_t pwlen) {
  // v = g^x mod N
  //printf("g(2): ");
  //print_bignum(ctx->g_ptr);
  // printf("N(2): ");
  //print_bignum(ctx->N_ptr);
  //printf("salt(2): %s\n", (char *)ctx->salt);
  //printf("pw(2): %s\n", (char *)pw);
  srp_compute_x(ctx, pw, pwlen);
  //printf("x(2): ");
  //print_bignum(&ctx->x);
  if (mp_exptmod(ctx->g_ptr, &ctx->x, &mp_N, &ctx->v) != MP_OKAY) { printf("13\n"); exit(-1); }
  //printf("v(2): ");
  //print_bignum(&ctx->v);
}

void
srp_select_random(srp_ctx *ctx, mp_int *out) {
  uint8_t randbytes[SRP_PRIME_SIZE/8];

  if (getrandom(randbytes, SRP_PRIME_SIZE/8, 0) != SRP_PRIME_SIZE/8) {
    printf("14\n");
    exit(-1);
  }
  if (mp_from_ubin(out, randbytes, SRP_PRIME_SIZE/8) != MP_OKAY) {
    printf("15\n");
    exit(-1);
  }
}

static void
srp_compute_A(srp_ctx *ctx) {
  srp_select_random(ctx, &ctx->a);
  if (mp_mod(&ctx->a, ctx->N_ptr, &ctx->a) != MP_OKAY) { printf("16\n"); exit(-1); }
  // A = g^a mod N
  if (mp_exptmod(ctx->g_ptr, &ctx->a, ctx->N_ptr, &ctx->A) != MP_OKAY) { printf("17\n"); exit(-1); }
  //printf("g(1): ");
  //print_bignum(ctx->g_ptr);
  //printf("a(1): ");
  //print_bignum(&ctx->a);
  //printf("N(1): ");
  //print_bignum(ctx->N_ptr);
  //printf("A(1): ");
  //print_bignum(&ctx->A);
}

void
srp_compute_B(srp_ctx *ctx) {
  // kv + g^b
  mp_int expr1; // kv
  mp_int expr2; // g^b
  
  if (mp_init(&expr1) != MP_OKAY)   { printf("18\n"); exit(-1); }
  if (mp_init(&expr2) != MP_OKAY)   { printf("19\n"); exit(-1); }

  srp_select_random(ctx, &ctx->b);
  if (mp_mod(&ctx->b, ctx->N_ptr, &ctx->b) != MP_OKAY) { printf("20\n"); exit(-1); }  
  
  if (mp_mulmod(ctx->k_ptr, &ctx->v, ctx->N_ptr, &expr1) != MP_OKAY) {
    printf("21\n");
    exit(-1);
  }
  if (mp_exptmod(ctx->g_ptr, &ctx->b, ctx->N_ptr, &expr2) != MP_OKAY) {
    printf("22\n");    
    exit(-1);
  }
  if (mp_addmod(&expr1, &expr2, ctx->N_ptr, &ctx->B)  != MP_OKAY) {
    printf("23\n");    
    exit(-1);    
  }
  mp_clear(&expr1);
  mp_clear(&expr2);

  //printf("k(2): ");
  //print_bignum(ctx->k_ptr);
  //printf("v(2): ");
  //print_bignum(&ctx->v);
  //printf("g(2): ");
  //print_bignum(ctx->g_ptr);
  //printf("b(2): ");
  //print_bignum(&ctx->b);
  //printf("B(2): ");
  //print_bignum(&ctx->B);
}

void
srp_compute_u(srp_ctx *ctx) {
  sha512_tag tag;
  uint8_t    buf[2*SRP_PRIME_SIZE/8] = {0,};
  size_t     outlen;
  int        error;
  mp_err     code;

  if ((code = mp_to_ubin(&ctx->A, buf, SRP_PRIME_SIZE/8, &outlen)) != MP_OKAY) {
    printf("24\n");
    printf("%s\n", mp_error_to_string(code));
    exit(-1);
  }
  if (mp_to_ubin(&ctx->B, buf+(SRP_PRIME_SIZE/8), SRP_PRIME_SIZE/8, &outlen) !=
      MP_OKAY) {
    printf("25\n");    
    exit(-1);
  }
  // TODO: do something w/ error value.
  sha512(&ctx->hctx, buf, sizeof(buf), &tag, &error);
  if (mp_from_ubin(&ctx->u, (const uint8_t *)&tag.bytes, SHA512_TAG_LENGTH) != MP_OKAY) {
    printf("26\n");    
    exit(-1);
  }
  if (mp_mod(&ctx->u, ctx->N_ptr, &ctx->u) != MP_OKAY) {     printf("27\n");exit(-1); }
}

// TODO: should be able to operate on expressions in-place,
// but need to double check.  Or at least re-use the temps
// w/o re-initing.
void
srp_party_1_compute_S(srp_ctx *ctx) {
  // s = pow((B - k*pow(g,x)), (a + u*x));
  mp_int expr1; // pow(g, x)
  mp_int expr2; // k*pow(g, x)
  mp_int expr3; // B - k*pow(g, x)
  mp_int expr4; // u*x
  mp_int expr5; // a + u*x

  //printf("s1(B,k,g,x,a,u,N)...\n");
  //printf("s1(");
  //print_bignum(&ctx->B);
  //printf(",");
  //print_bignum(ctx->k_ptr);
  //printf(",");
  //print_bignum(ctx->g_ptr);
  //printf(", ");
  //print_bignum(&ctx->x);
  //printf(", ");
  //print_bignum(&ctx->a);
  //printf(", ");
  //print_bignum(&ctx->u);
  //printf(", ");
  //print_bignum(ctx->N_ptr);
  //printf(")\n");

  printf("Do I get through here?\n");
  if (mp_init(&expr1) != MP_OKAY) { exit(-1); }    
  if (mp_init(&expr2) != MP_OKAY) { exit(-1); }
  if (mp_init(&expr3) != MP_OKAY) { exit(-1); }  
  if (mp_init(&expr4) != MP_OKAY) { exit(-1); }
  if (mp_init(&expr5) != MP_OKAY) { exit(-1); }  

  if (mp_exptmod(ctx->g_ptr, &ctx->x, ctx->N_ptr, &expr1) != MP_OKAY) { exit(-1); }
  if (mp_mul(ctx->k_ptr, &expr1, &expr2) != MP_OKAY)   { exit(-1); }
  if (mp_sub(&ctx->B, &expr2, &expr3) != MP_OKAY)      { exit(-1); }
  if (mp_mul(&ctx->u, &ctx->x, &expr4) != MP_OKAY)     { exit(-1); }
  if (mp_add(&ctx->a, &expr4, &expr5)  != MP_OKAY)     { exit(-1); }
  if (mp_exptmod(&expr3, &expr5, ctx->N_ptr, &ctx->S) != MP_OKAY) { exit(-1); }
  printf("Yes.\n");
  
  mp_clear(&expr1);
  mp_clear(&expr2);
  mp_clear(&expr3);
  mp_clear(&expr4);
  mp_clear(&expr5);
  //printf("S ?= ");
  //print_bignum(&ctx->S);
  //printf("\n");
}

void
srp_party_2_compute_S(srp_ctx *ctx) {
  // pow(A*pow(v, u), b);
  mp_int expr1; // pow(v, u)
  mp_int expr2; // A*pow(v, u)

  //printf("s2(A, v, u, b, N)\n");
  //printf("s2(");
  //print_bignum(&ctx->A);
  //printf(",");
  //print_bignum(&ctx->v);
  //printf(",");
  //print_bignum(&ctx->u);
  //printf(",");
  //print_bignum(&ctx->b);
  //printf(",");
  //print_bignum(ctx->N_ptr);
  //printf(")\n");

  printf("Do I get through here?\n");
  if (mp_init(&expr1) != MP_OKAY)      { exit(-1); }
  if (mp_init(&expr2) != MP_OKAY)      { exit(-1); }

  if (mp_exptmod(&ctx->v, &ctx->u, ctx->N_ptr, &expr1) != MP_OKAY) { exit(-1); }
  if (mp_mulmod(&expr1, &ctx->A, ctx->N_ptr, &expr2)   != MP_OKAY) { exit(-1); }
  if (mp_exptmod(&expr2, &ctx->b, ctx->N_ptr, &ctx->S) != MP_OKAY) { exit(-1); }
  printf("Yes.\n");

    // Old and busted
  //if (mp_mulmod(&ctx->A, &ctx->v, ctx->N_ptr, &expr1) != MP_OKAY) { exit(-1); }
  //  if (mp_exptmod(&expr1, &ctx->u, ctx->N_ptr, &expr2) != MP_OKAY) { exit(-1); }
  //if (mp_exptmod(&expr2, &ctx->b, ctx->N_ptr, &ctx->S) != MP_OKAY) { exit(-1); }
  
  mp_clear(&expr1);
  mp_clear(&expr2);
  //printf("S ?= ");
  //print_bignum(&ctx->S);
  //printf("\n");
}

void
srp_party_1_step_1(srp_ctx *ctx) {
  srp_compute_A(ctx);
}

bool
srp_check_party_1_params(srp_ctx *ctx) {
  // Party 1 fails if A mod N == 0.
  mp_int tmp;
  bool   ret = true;

  if (mp_init(&tmp) != MP_OKAY)                { printf("a\n"); exit(-1); }
  if (mp_mod(&ctx->A, ctx->N_ptr, &tmp) != MP_OKAY) { printf("b\n"); exit(-1); }
  if (mp_cmp_mag(&tmp, ctx->Zero_ptr) == MP_EQ) {
    ret = false;
  }
  
  mp_clear(&tmp);
  return ret;
}

bool
srp_check_party_2_params(srp_ctx *ctx) {
  // Party 2 fails if B mod N == 0 or u == 0.
  mp_int tmp;
  bool   ret = true;

  if (mp_init(&tmp) != MP_OKAY)                     { printf("c\n");exit(-1); }
  if (mp_mod(&ctx->B, ctx->N_ptr, &tmp) != MP_OKAY) { printf("d\n");exit(-1); }
  if (mp_cmp_mag(&tmp, ctx->Zero_ptr) == MP_EQ) {
    ret = false;
  }
  if (mp_cmp_mag(&ctx->u, ctx->Zero_ptr) == MP_EQ) {
    ret = false;
  }
  mp_clear(&tmp);
  return ret;

}

void
compute_key_material(srp_ctx *ctx) {
  // Hash(S)...
  // Need to export the number to a consistent byte stream.
  // 256 bits of the tag to the proof, 256 to the key
  int      error;
  size_t   outlen;
  uint8_t *buf;
  size_t   buflen;

  buflen = mp_ubin_size(&ctx->S);
  buf    = (uint8_t *)malloc(buflen);
  
  if (mp_to_ubin(&ctx->S, buf, buflen, &outlen) != MP_OKAY) {printf("e\n"); exit(-1); }
  sha512_update(&ctx->hctx, buf, outlen, &error);
  sha512_final (&ctx->hctx, &ctx->keymatter, &error);
  free(buf);
}

// The design doc proof is overkill.  Currently doing less.
void
compute_proofs(srp_ctx *ctx) {
  int      error;
  uint32_t be_len = htonl(ctx->namelen);
  
  sha512_update(&ctx->hctx, H_N.bytes, sizeof(H_N), &error);
  sha512_update(&ctx->hctx, (const uint8_t *)&be_len, sizeof(be_len), &error);
  sha512_update(&ctx->hctx, ctx->username, ctx->namelen, &error);
  sha512_update(&ctx->hctx, ctx->keymatter.bytes, sizeof(ctx->keymatter), &error);
  sha512_final (&ctx->hctx, &ctx->proof1, &error);
  sha512_update(&ctx->hctx, ctx->proof1.bytes, sizeof(&ctx->proof1), &error);
  sha512_update(&ctx->hctx, ctx->keymatter.bytes
		, sizeof(ctx->keymatter), &error);
  sha512_final (&ctx->hctx, &ctx->proof2, &error);
}

void
srp_party_2_step_1(srp_ctx *ctx) {
  //printf("A(2): ");
  //print_bignum(&ctx->A);
  // TODO: handle this gracefully.
  srp_compute_B(ctx);
  srp_compute_u(ctx);
  //printf("u(2):");
  //print_bignum(&ctx->u);
  srp_party_2_compute_S(ctx);

  printf("Server computed S:");
  print_bignum(&ctx->S);
  printf("\n");
  if (!srp_check_party_1_params(ctx)) { printf("Fuck.\n"); return; }
  compute_key_material(ctx);
  compute_proofs(ctx);
}

void
srp_party_1_step_2(srp_ctx *ctx, uint8_t *pw, uint32_t pwlen) {
  //printf("B(1): ");
  //print_bignum(&ctx->B);
  srp_compute_u(ctx);
  //printf("u(1):");
  //print_bignum(&ctx->u);
  srp_compute_x(ctx, pw, pwlen);
  //printf("x(1): ");
  //print_bignum(&ctx->x);
  srp_party_1_compute_S(ctx);
  //printf("Client computed S:");
  //print_bignum(&ctx->S);
  //printf("\n");
  if (!srp_check_party_2_params(ctx)) { return; }
  compute_key_material(ctx);
  compute_proofs(ctx);
}

bool
srp_party_2_step_2(srp_ctx *ctx, sha512_tag *received_proof) {
  if (memcmp(&ctx->proof1, received_proof, sizeof(sha512_tag))) {
    return false;
  }
  return true;
}

bool
srp_party_1_step_3(srp_ctx *ctx, sha512_tag *received_proof) {
  if (memcmp(&ctx->proof2, received_proof, sizeof(sha512_tag))) {
    return false;
  }
  return true;
}

#ifdef TEST_SRP
//  mp_to_decimal(&res, buf, 1024);
//  mp_to_hex(&res, buf2, 1024);
//  err = mp_prime_is_prime(&res, 8, &result);

int main(int argc, char **argv) {
  srp_ctx client_ctx, server_ctx;
  char *pw = "testpw";

  srp_init(&client_ctx);
  srp_init(&server_ctx);
  client_ctx.username = (uint8_t *)"test";
  client_ctx.namelen  = strlen((char *)client_ctx.username);
  server_ctx.salt     = (uint8_t *)"testsalt";
  server_ctx.saltlen  = strlen((char *)server_ctx.salt);

  srp_compute_v(&server_ctx, (uint8_t *)pw, strlen(pw));
  srp_party_1_step_1(&client_ctx);
  // User -> Host: username, A
  server_ctx.username = client_ctx.username;
  server_ctx.namelen  = client_ctx.namelen;
  memcpy((void *)&(server_ctx.A), &(client_ctx.A), sizeof(client_ctx.A));
  srp_party_2_step_1(&server_ctx);
  
  // Host -> User: s, B
  client_ctx.salt     = server_ctx.salt;
  client_ctx.saltlen  = server_ctx.saltlen;
  memcpy((void *)&(client_ctx.B), &(server_ctx.B), sizeof(server_ctx.B));  
  srp_party_1_step_2(&client_ctx, (uint8_t *)pw, strlen(pw));


  if (!srp_party_2_step_2(&server_ctx, &client_ctx.proof1)) {
    printf("Proof failed.\n");
  } else {
    printf("Done!\n");
  }
}
#endif
