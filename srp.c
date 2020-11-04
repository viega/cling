#include "libtommath/tommath.h"
#include <stdlib.h>
#include <sys/random.h>

#include "sha512.h"

#define SRP_PRIME_SIZE 2048
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

static mp_int mp_N;
static mp_int mp_g;
static mp_int mp_k;
static bool   inited = false;

typedef struct {
  mp_int    *N_ptr; // Our large public safe prime (above).
  mp_int    *g_ptr; // 2.
  mp_int    *k_ptr; // A multiplier parameter: H(N,g)
  mp_int     u; // Random scrambling parameter;
  mp_int     a; // Secret ephemeral value used to compute A
  mp_int     b; // Secret ephemeral value used to compute B
  mp_int     A; // The public ephemeral value sent by the initiator
  mp_int     B; // The public ephemeral value sent by the receiver.
  mp_int     x; // The private key.
  mp_int     v; // Password verifier.
  mp_int     S; // The session key, prior to applying our hash function
  uint8_t   *salt; // A (public) salt value.
  uint8_t   *username;
  uint32_t   saltlen;
  uint32_t   namelen;
  sha512_ctx hctx;
} srp_ctx;


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
    exit(-1);
  }
}

void
srp_init(srp_ctx *ctx) {
  sha512_initialize(&ctx->hctx);
  if (!inited) {
    if (mp_init(&mp_N) != MP_OKAY)                    { exit(-1); }
    if (mp_from_ubin(&mp_N, N, sizeof(N)) != MP_OKAY) { exit(-1); }
    if (mp_init_i32(&mp_g, 2) != MP_OKAY)             { exit(-1); }
    srp_compute_k(ctx);
  }
  ctx->N_ptr = &mp_N;
  ctx->g_ptr = &mp_g;
  ctx->k_ptr = &mp_k;
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
    exit(-1);
  }
}

void
srp_compute_v(srp_ctx *ctx) {
  // v = g^x mod N
  if (mp_exptmod(ctx->g_ptr, &ctx->x, &mp_N, &ctx->v) != MP_OKAY) { exit(-1); }
}

void
srp_select_random(srp_ctx *ctx, mp_int *out) {
  uint8_t randbytes[SRP_PRIME_SIZE/8];
  
  if (getrandom(randbytes, SRP_PRIME_SIZE/8, 0) != SRP_PRIME_SIZE) {
    exit(-1);
  }
  if (mp_from_ubin(out, randbytes, SRP_PRIME_SIZE/8) != MP_OKAY) {
    exit(-1);
  }
}

void
srp_initiator_compute_A(srp_ctx *ctx) {
  srp_select_random(ctx, &ctx->a);
  // A = g^a mod N
  if (mp_exptmod(ctx->g_ptr, &ctx->a, ctx->N_ptr, &ctx->A) != MP_OKAY) { exit(-1); }
}

void
srp_compute_B(srp_ctx *ctx) {
  // kv + g^b
  mp_int expr1; // kv
  mp_int expr2; // g^b
  
  if (mp_init(&expr1) != MP_OKAY)   { exit(-1); }
  if (mp_init(&expr2) != MP_OKAY)   { exit(-1); }

  srp_select_random(ctx, &ctx->b);
  if (mp_mulmod(ctx->k_ptr, &ctx->v, ctx->N_ptr, &expr1) != MP_OKAY) {
    exit(-1);
  }
  if (mp_exptmod(ctx->g_ptr, &ctx->b, ctx->N_ptr, &expr2) != MP_OKAY) {
    exit(-1);
  }
  if (mp_addmod(&expr1, &expr2, ctx->N_ptr, &ctx->B)  != MP_OKAY) {
    exit(-1);    
  }
  mp_clear(&expr1);
  mp_clear(&expr2);
}

void
srp_compute_u(srp_ctx *ctx) {
  sha512_tag tag;
  uint8_t    buf[2*SRP_PRIME_SIZE/8] = {0,};
  size_t     outlen;
  int        error;

  if (mp_to_ubin(&ctx->A, buf, SRP_PRIME_SIZE/8, &outlen) != MP_OKAY) {
    exit(-1);
  }
  if (mp_to_ubin(&ctx->B, buf+(SRP_PRIME_SIZE/8), SRP_PRIME_SIZE/8, &outlen) !=
      MP_OKAY) {
    exit(-1);
  }
  // TODO: do something w/ error value.
  sha512(&ctx->hctx, buf, sizeof(buf), &tag, &error);
  if (mp_from_ubin(&ctx->u, (const uint8_t *)&tag.bytes, SHA512_TAG_LENGTH) != MP_OKAY) {
    exit(-1);
  }
}

// TODO: should be able to operate on expressions in-place,
// but need to double check.  Or at least re-use the temps
// w/o re-initing.
void
srp_initiator_compute_S(srp_ctx *ctx) {
  // H(pow((B - pow(k*g,x)), (a + u*x)));
  mp_int expr1; // k*g
  mp_int expr2; // pow(k*g, x)
  mp_int expr3; // B - pow(k*g, x)
  mp_int expr4; // u*x
  mp_int expr5; // a + u*x

  if (mp_init(&expr1) != MP_OKAY) { exit(-1); }    
  if (mp_init(&expr2) != MP_OKAY) { exit(-1); }
  if (mp_init(&expr3) != MP_OKAY) { exit(-1); }  
  if (mp_init(&expr4) != MP_OKAY) { exit(-1); }
  if (mp_init(&expr5) != MP_OKAY) { exit(-1); }  
  
  if (mp_mulmod(ctx->k_ptr, ctx->g_ptr,
		ctx->N_ptr, &expr1)                   != MP_OKAY) { exit(-1); }
  if (mp_exptmod(&expr1, &ctx->x, ctx->N_ptr, &expr2) != MP_OKAY) { exit(-1); }
  if (mp_submod(&ctx->B, &expr2, ctx->N_ptr, &expr3)  != MP_OKAY) { exit(-1); }
  if (mp_mulmod(&ctx->u, &ctx->x, ctx->N_ptr, &expr4) != MP_OKAY) { exit(-1); }
  if (mp_addmod(&ctx->a, &expr4, ctx->N_ptr, &expr5)  != MP_OKAY) { exit(-1); }
  if (mp_exptmod(&expr3, &expr5, ctx->N_ptr, &ctx->S) != MP_OKAY) { exit(-1); }

  mp_clear(&expr1);
  mp_clear(&expr2);
  mp_clear(&expr3);
  mp_clear(&expr4);
  mp_clear(&expr5);  
}

void
srp_receiver_compute_S(srp_ctx *ctx) {
  // pow(pow(A*v, u), b);
  mp_int expr1; // A*v
  mp_int expr2; // pow(A*v, u)

  if (mp_init(&expr1) != MP_OKAY)      { exit(-1); }
  if (mp_init(&expr2) != MP_OKAY)      { exit(-1); }  

  if (mp_mulmod(&ctx->A, &ctx->v, ctx->N_ptr, &expr1) != MP_OKAY) { exit(-1); }
  if (mp_exptmod(&expr1, &ctx->u, ctx->N_ptr, &expr2) != MP_OKAY) { exit(-1); }
  if (mp_exptmod(&expr2, &ctx->b, ctx->N_ptr, &ctx->S) != MP_OKAY) { exit(-1); }
  
  mp_clear(&expr1);
  mp_clear(&expr2);
}

//  mp_to_decimal(&res, buf, 1024);
//  mp_to_hex(&res, buf2, 1024);
//  err = mp_prime_is_prime(&res, 8, &result);

int main(int argc, char **argv) {
  //srp_init();  
}

