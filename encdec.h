#ifndef __GCM_ENCDEC_H__
#define __GCM_ENCDEC_H__

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

// Note that, while these values theoretically have some flexibility,
// there are good reasons to never change them.

// The authentication tag size can theoretically be shortened, but
// this has an outsized impact on the forgeability of messages, so
// leave at 16.
#define GCM_TAG_LEN 16
// 12 bytes is, by far, the most efficient length for a GCM
// initialization vector.  Keeping it this size avoids paying the
// price of hashing the IV.
#define GCM_IV_LEN  12
// We are going ahead and using AES-256 for all sessions.  That is, 32
// byte (256 bit) keys.  128 bits is generally considered "enough" but
// the prevalance of hardware acceleration is such that we don't
// recommend smaller keys.  If we add future flexibility, this is the
// only parameter that we'd consider changing.
#define AES_KEYLEN  32

// In this library, when we initialize a GCM context, we must indicate
// whether we are the client or the server.  We maintain separate
// nonce spaces for the two sides, so that messages don't have to be
// sent in lockstep.
#define ROLE_CLIENT 0
#define ROLE_SERVER 1

// This value specifies the total number of messages either side of
// the connection will allow to be sent, before terminating.  Note
// that this is not the total number of encryption operations, it's
// the total number of messages.  To be conservative, we limit it to
// 2^20 (over 2M messages)
#define MAX_MESSAGES 0x00200000

// We will only ever use 24 bits for the message counter.
// For the rest of the nonce, we will reserve a byte for
// connection state, and then fill the rest with random
// bits at the beginning of the connection.

// bytes 0-3:  Random bytes chosen at message encrypt time,
//             XOR'd with a high-precision timer.
// bytes 4-7:  Random bytes chosen at message encrypt time,
//             XOR'd with the PID of the current process.
// byte  8:    Flags that hold connection state (like identifying the
//             origin as the sender or receiver)
// bytes 9-11: The 24-bit message counter.

// Indexing into a 32-bit array, which word contains the appropriate value?
#define GCM_HPT_IX     0
#define GCM_PID_IX     1
#define GCM_MSG_CTR_IX 2

// The message counter is stored in a 32 bit word, but is only
// a 24-bit value.  The rest of the word/half word is reserved for
// flags that indicate the sending context (e.g., if the client
// sent a message or the server did), in order to avoid nonce
// reuse.  Below are masks that extract either the counter, or
// any flags we use.
//
// Note that we will operate on this word using the host machine's
// integer operations, which may have an incompatable byte ordering
// with the underlying byte stream (we store data and put it on the
// wire in big endian).  Therefore, these masks should only be applied
// once the word is loaded in HOST byte order.

// The most significant bit is on when the server-side originates
// a message, and off when it's the client.
#define F_SERVER_ORIGIN 0x80000000
#define F_CLIENT_ORIGIN 0x00000000
// This flag may be used to help negotiate retransmissions
// when I get that far.  It's just a placeholder at the moment.
#define F_CONTROL_MSG   0x40000000
// Right now, F_CTR_OVERFLOW is also unused; instead, the check
// is on a comparison against MAX_MESSAGES.
#define F_CTR_OVERFLOW  0x01000000
// When treating the lower 32 bits of the IV as an int, this
// removes the flags, and gives us just the counter.
#define MASK_CTR        0x00ffffff
// Masks out the lower 32 bits of an 64-bit int, which we use
// when getting clock data.
#define MASK_LOWER_32   ((uint64_t)0xffffffff)

#define ERR_DECRYPT_FAIL  EBADMSG      // Proxy'd from kernel
#define ERR_ENCRYPT_LIMIT ECONNABORTED // Piggybacking on code
#define ERR_BAD_PLAINTEXT EINVAL       // Piggybacking on code
#define ERR_BAD_ORIGIN    EPROTO       // Piggybacking on code

// For our perposes, AES keys really only need to be an array of
// bytes.  We use a fixed-size key, so don't even need to keep
// track of the key size.
typedef struct {
    uint8_t key[AES_KEYLEN];
} aes_key_t;

// Note that nonces are stored in network byte order, so when we pull
// from nonce.u.ints we need to call ntohl (and the reverse when we
// store this way).  This data structure should be memory-compatable
// with the kernel's struct af_alg_iv with a 12 byte nonce.  However,
// we lay it out this way to make it easier for us to operate on the
// nonce in different ways depending on our needs.
typedef struct {
    uint32_t ivlen;
    union {
        uint32_t ints[3];
        uint8_t  bytes[12];
    } u;
} gcm_iv_t;

// These macros assume you're operating on an object of type
// gcm_iv_t, not a reference to an object.  We do this because
// IVs are embedded in gcm_ctx and gcm_str, and so we'll be
// holding a pointer to those objects; nothing will be holding
// pointers to IVs.
#define IV_GET_CTR_WORD(iv)    (ntohl((iv).u.ints[GCM_MSG_CTR_IX]))
#define IV_SET_CTR_WORD(iv, c) ((iv).u.ints[GCM_MSG_CTR_IX] = htonl(c))
#define IV_GET_ORIGIN(iv)      (IV_GET_CTR_WORD(iv) & F_SERVER_ORIGIN)

// This context object holds all the state associated with a single
// symmetric encryption session.  It contains references to the file
// descriptors in use to talk to the kernel, and information about
// initialization vectors for communication in both directions.  It
// also contains a boolean flag that indicates that the session should
// be terminated for reaching the limit of messages sent.
//
// Note that we do NOT store the key in this structure; once we pass
// it to the kernel, it's best not to keep any key material in
// userland.  To that end, we will generally attempt to wipe the key
// from memory after we key the cipher.
//
// In the future we might support state resumption, at which point we
// will look to securely store key info (requiring decrypting at
// startup).

typedef struct {
    int      listen_fd;
    int      fd;
    gcm_iv_t encr_iv; // IV for encrypting messages.
    gcm_iv_t decr_iv; // IV for decrypting messages.
    bool     encrypt_limit;
    uint32_t origin_bit;
} gcm_ctx;

// The gcm_str data type is used to hold plaintext and ciphertext
// both, and accounts for the metadata associated with them.  Please
// only use the APIs for accessing these, to avoid any kind of memory
// error.
typedef struct {
    // The first fields are internal accounting.
    // Note that the total length of the input payload
    // should be aad_length + msg_length,
    // and the total length of the output payload
    // should be msg_length + tag_length.

    uint32_t msg_length; // length of the plaintext/ciphertext.
    uint32_t tag_length; // Either 16 or 0; 16 if it's ct, 0 if it's plaintext.
    gcm_iv_t iv;         // Initialization Vector used for this message.
    uint32_t aad_length;
    // When accessing a message, we should be able to address the pt and ct
    // By requesting them, and we also need to know which iovec is the input
    // and output.   So for convenience, store the two vectors in two different
    // sets of points.
    struct iovec *in_iov;
    struct iovec *out_iov;
    struct iovec *pt_iov;
    struct iovec *ct_iov;
    // For input to an operation, the kernel can gather strings that are
    // scattered around memory.  Each iovec holds a pointer to a string
    // (along w/ an indication of size), and in_iov is actually a pointer
    // to an ARRAY of struct iovec objects.  The iov_count field specifies
    // how many items are in the in_iov array.
    uint32_t      iov_count;
    uint8_t       payload[0];
} gcm_str;

bool gcm_initialize(gcm_ctx *, aes_key_t *, int32_t);
bool gcm_encrypt(gcm_ctx *, gcm_str *, int *);
bool gcm_decrypt(gcm_ctx *, gcm_str *, int *);
#endif
