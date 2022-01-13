#include "libtommath/tommath.h"
#include "sha512.h"

typedef struct {
    // We put pointers to the static value just to make the code a bit more
    // clear (for me at least).
    mp_int    *N_ptr;    // Our large public safe prime (above).
    mp_int    *g_ptr;    // 2.
    mp_int    *k_ptr;    // A multiplier parameter: H(N,g)
    mp_int    *Zero_ptr; // A pointer to zero.
    mp_int     u;        // Random scrambling parameter;
    mp_int     a;        // Secret ephemeral value used to compute A
    mp_int     b;        // Secret ephemeral value used to compute B
    mp_int     A; // The public ephemeral value sent by party 1 (the initiator)
    mp_int     B; // The public ephemeral value sent by party 2
    mp_int     x; // The private key.
    mp_int     v; // Password verifier.
    mp_int     S; // The session key, prior to applying our hash function
    uint8_t   *salt; // A (public) salt value.
    uint8_t   *username;
    uint32_t   saltlen;
    uint32_t   namelen;
    sha512_ctx hctx;
    sha512_tag keymatter;
    sha512_tag proof1;
    sha512_tag proof2;
} srp_ctx;

void srp_init(srp_ctx *);
void srp_party_1_step_1(srp_ctx *);
void srp_party_1_step_2(srp_ctx *, uint8_t *, uint32_t);
bool srp_party_1_step_3(srp_ctx *, sha512_tag *);

void srp_party_2_step_1(srp_ctx *);
bool srp_party_2_step_2(srp_ctx *, sha512_tag *);
void srp_compute_v(srp_ctx *, uint8_t *, uint32_t);

char *build_hex_dump(unsigned char *bytes, uint32_t len);
