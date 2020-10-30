#include <sys/types.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <linux/if_alg.h>
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
#define GCM_IV_LEN   12
// We are going ahead and using AES-256 for all sessions.  That is, 32
// byte (256 bit) keys.  128 bits is generally considered "enough" but
// the prevalance of hardware acceleration is such that we don't
// recommend smaller keys.  If we add future flexibility, this is the
// only parameter that we'd consider changing.
#define AES_KEYLEN 32

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
#define MAX_MESSAGES     0x00200000

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
#define GCM_HPT_IX      0
#define GCM_PID_IX      1
#define GCM_MSG_CTR_IX  2

// The first 64 bits of the IV are data supplied by the sender, and
// must be used by the recipient to decrypt.  We call this the
// "noncelet" (the IV is technically a nonce itself, and this is a
// one-time value that is part of the IV).  We store the noncelet as a
// byte array, and use NONCELET_LEN to indicate the length in bytes.
#define NONCELET_LEN    8

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
#define F_SERVER_ORIGIN  0x80000000
// This flag may be used to help negotiate retransmissions
// when I get that far.  It's just a placeholder at the moment.
#define F_CONTROL_MSG    0x40000000
// Right now, F_CTR_OVERFLOW is also unused; instead, the check 
// is on a comparison against MAX_MESSAGES.
#define F_CTR_OVERFLOW   0x01000000
// When treating the lower 32 bits of the IV as an int, this
// removes the flags, and gives us just the counter.
#define MASK_CTR         0x00ffffff
// Masks out the lower 32 bits of an 64-bit int, which we use
// when getting clock data.
#define MASK_LOWER_32    ((uint64_t)0xffffffff)

// This is the specification we need to pass to the kernel
// when we create a file descriptor, in order for writes
// to that descriptor to encrypt using GCM.
// I do not yet know if this automatically selects NI when
// available, or if we need to add the logic for that.
// That's a TODO item.
struct sockaddr_alg gcm_spec = {
    .salg_family = AF_ALG,
    .salg_type   = "aead",
    .salg_name   = "gcm(aes)"
};

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
  uint32_t   ivlen;
  union {
    uint32_t ints [3];
    uint8_t  bytes[12];
  } u;
} gcm_iv_t;

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
  int       listen_fd;
  int       fd;
  gcm_iv_t  encr_iv; // IV for encrypting messages.
  gcm_iv_t  decr_iv; // IV for decrypting messages.
  bool      encrypt_limit;
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
  
  uint32_t msg_length;  // length of the plaintext/ciphertext.
  uint32_t tag_length;  // Either 16 or 0; 16 if it's ct, 0 if it's plaintext.
  uint8_t  noncelet[NONCELET_LEN];
  uint32_t aad_length;
  bool     plaintext;
  struct   iovec *iov;
  uint8_t  payload[0];
} gcm_str;

// This private function sets up the initial IV for gcm.
// The IV consists of 3 parts, per above...
// 1) 8 random bytes per-message selected by the sender,
//    which we initialize to 0
// 2) A one byte flag field to indicate the sending context
// 3) A three byte message counter that should start at 0.
//    For the sender, the IV will always indicate the message
//    index for the NEXT message to be encrypted, whereas for
//    decryption, it indicates the minimum acceptable IV for
//    a received message (if drops are okay).
//
// It's incredibly critical for each pair of: key, nonce to
// NEVER be reused in an encryption operation.
//
// Ideally, each key will get used only once (due to a secure key
// exchange function, where keys are a function of mutual randomness).
//
// However, there can be cases where we accidentally end up using the
// same key to send two different messages using the same nonce.
// Two conditions come to mind:
// 
// 1) A process forks, and both child processes continue to send
//    messages using the same nonce state.
// 2) A VM restores, and reverts to old state.  Sure, the other
//    end of the connection will generally NOT accept the messages
//    (because it will have already seen the message sequence #s).
//    However, an attacker can still leverage the two outputs.
//
// There's still some risk that in both of these cases, the system
// randomness will be poor enough that the random piece could end up
// the same, if we just naively ask for system randomness.  However,
// in the 2nd case there will definitely be clock skew between the two
// operations.  And, generally there will be skew in the first case
// too, the question is more if we can measure it appropriately.
//
// To that end, we mix the Linux-specific BOOTTIME clock into the
// nonce, which ignores date changes, but takes into account any time
// a machine is suspended.  So it will definitely address case #2, and
// should help with case #1.
//
// To address the problem in case #1, we also mix the local
// process ID into the nonce (any fork will get a new PID).
//
// To do the mixing, we XOR the lowest 4 bytes of our high precision
// timer into the first half of the random string, and XOR the PID
// (which is 32 bits) into the second half of the random string.
// However, this is handled when a message is encrypted, not when IVs
// are initialized :-)

static void
gcm_init_ivs(gcm_ctx *ctx, int role) {
  // Zero out the IV structures.
  memset(&(ctx->encr_iv), 0, sizeof(gcm_iv_t));
  memset(&(ctx->decr_iv), 0, sizeof(gcm_iv_t));
  // IV length is always 12.
  ctx->encr_iv.ivlen = GCM_IV_LEN;
  ctx->decr_iv.ivlen = GCM_IV_LEN;
  // Set the flag indicating which nonce is for server-originated
  // messages.  This flag is in the most significant byte of the final
  // 32 bits, which is otherwise occupied by the message counter.
  if (role == ROLE_CLIENT) {
    ctx->encr_iv.u.ints[GCM_MSG_CTR_IX] = htonl(F_SERVER_ORIGIN);
  } else {
    ctx->encr_iv.u.ints[GCM_MSG_CTR_IX] = htonl(F_SERVER_ORIGIN);
  }
}

// This function is used to key a gcm_ctx, and set up its internal
// state.  It's meant to be used for new sessions with unique session
// keys.  If we eventually add the ability to resume sessions (after
// the process on either side dies), then we will have a different API
// for the state load / resumption.
//
// This currently isn't doing any error checking, which is definitely
// TODO soon.
bool
gcm_initialize(aes_key_t *key,
	       int32_t    role,
	       gcm_ctx   *ctx) {
  ctx->listen_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (bind(ctx->listen_fd,
	   (struct sockaddr *)&gcm_spec,
	   sizeof(gcm_spec)) < 0) {
    perror("bind");
    return false;
  }
  if (setsockopt(ctx->listen_fd,
		 SOL_ALG,
		 ALG_SET_AEAD_AUTHSIZE,
		 NULL,
		 GCM_TAG_LEN) < 0) {
    perror("setsockopt:tag size");
    return false;
  }
  if (setsockopt(ctx->listen_fd,
		 SOL_ALG,
		 ALG_SET_KEY,
		 key->key,
		 AES_KEYLEN) < 0) {
    perror("setsockopt:key");
    return false;
  }
  ctx->fd = accept(ctx->listen_fd, NULL, 0);
  if (ctx->fd < 0) {
    perror("accept");
    return false;
  }
  gcm_init_ivs(ctx, role);
  ctx->encrypt_limit = false;
  return true;
}

// The kernel uses a pretty regular interface for encryption and
// decryption.  This code is used by both to perform the desired
// operation, and read the result.
bool
gcm_send_kernel_msg(gcm_ctx *ctx, gcm_str *in, gcm_str *out,
		    uint32_t operation, int *error) {
  // Set up the encryption request.  The struct msghdr object is
  // actually the entire message that we will pass to the kernel --
  // the hdr in msghdr is a bit of a misnomer.
  //
  // However, there are proper HEADERS to send... meta-data needed
  // for the encryption.  Particularly, the kernel needs to know
  // if it should perform an encryption operation or a decryption
  // operation.  It needs the IV specific to the message.  And, it
  // needs to know how much of the message is associated data, if any.
  // That metadata is going to be loaded up using records of type
  // struct cmsghdr.  We'll actually create 3 such records, and those
  // records will all live in memory that we'll allocate on the stack
  // (see the variable mbuf below).

  struct msghdr   msg = {0,};
  struct cmsghdr *header = NULL;
  
  // We must pass the kernel metadata about what we're about to
  // encrypt.  The metadata payload consists of the following 3 items:
  // 1) A 32-bit word indicating the operation (encryption / decryption)
  // 2) The initialization vector for the encryption operation
  // 3) A 32-bit word indicating the amount of associated data
  //
  // We have to pass this in 3 separate CMSGs, for which we need to
  // provide a single buffer.  We'll use the stack for this, but
  // we need to use the CMSG_SPACE macro to ensure the sizing is
  // correct.
  int  mbuf_len = CMSG_SPACE(sizeof(uint32_t)) +  // operation
                  CMSG_SPACE(sizeof(gcm_iv_t)) +  // IV
                  CMSG_SPACE(sizeof(uint32_t));   // AAD len
  uint8_t mbuf[mbuf_len];

  memset(mbuf, 0, mbuf_len);

  msg.msg_control    = (void *)mbuf;
  msg.msg_controllen = mbuf_len;
  // Note that IOV stands for "IO vector",
  // meaning we can send in an array of pointers to strings for the
  // kernel to treat as a consecutive message.  For right now, we
  // will just one-shot encrypt, instead of incrementally doing so.
  msg.msg_iov        = in->iov;
  msg.msg_iovlen     = 1;

  // Here, we're using the kernel's APIs for adding metadata to our
  // message.
  header                         = CMSG_FIRSTHDR(&msg);
  header->cmsg_level             = SOL_ALG;
  header->cmsg_type              = ALG_SET_OP;
  header->cmsg_len               = CMSG_LEN(sizeof(uint32_t));
  // We can't just reference a cmsg_data field, it needs to be computed.
  *(uint32_t *)CMSG_DATA(header) = operation;

  header                         = CMSG_NXTHDR(&msg, header);
  header->cmsg_level             = SOL_ALG;
  header->cmsg_type              = ALG_SET_IV;
  header->cmsg_len               = CMSG_SPACE(sizeof(gcm_iv_t));
  memcpy(CMSG_DATA(header), &ctx->encr_iv, sizeof(gcm_iv_t));

  // This needs to be sent, even if there is no AAD.
  header                         = CMSG_NXTHDR(&msg, header);
  header->cmsg_level             = SOL_ALG;
  header->cmsg_type              = ALG_SET_AEAD_ASSOCLEN;
  header->cmsg_len               = CMSG_LEN(sizeof(uint32_t));
  *(uint32_t *)CMSG_DATA(header) = in->aad_length;
  
  if (sendmsg(ctx->fd, &msg, 0) < 0) {
    *error = errno;
    perror("sendmsg");
    return false;
  }

  // At this point, we've passed the input to the kernel.  We will
  // now read out the result.  A couple of things to note here:
  // 1) This is a blocking operation, not async. But, given it's
  //    symmetric crypto, it should be sufficiently fast.
  // 2) The kernel requires the output buffer to be the same size as
  //    the input buffer (minus the tag if it's a decryption operation).
  //    In particular, this means that, if there is AAD, the output
  //    buffer must be big enough to hold both the AAD and the message.
  //    It does this so that it can do in-place operations.
  
  uint32_t outlen = in->msg_length; 
  ssize_t  n;
  uint8_t *outptr;

  if (operation == ALG_OP_ENCRYPT) {
    outlen += GCM_TAG_LEN;
  }
  outptr = out->iov->iov_base;

  while (outlen) {
    n = read(ctx->fd, out, outlen);
    if (n > 0) {
      outptr += n;
      outlen -= n;
    } else {
      if (errno != EINTR) {
	*error = errno;
	perror("read");
	return false;
      }
    }
  }
  
  return true;
}

// We require AAD and plaintext to be sequential in memory, as the kernel
// expects that, and we don't want to do any unnecessary copying of strings.
// @param ctx       The gcm context to use for encrypting.
// @param in        AAD || Plaintext
// @param total_len length of AAD||Plaintext in bytes
// @param aad_len   length of AAD
// @param out       Pointer to memory for storing output
// @param outlen    Length of the output buffer.  Must be the size of the plaintext plus 16 bytes.
// @param noncelet  A pointer to memory to hold a random 32-bit word used in the iv.
// @param error     Error code, if appropriate
// @return True if successful, false if error.

// Note that the out string must be pre-allocated to the right length
// (allowing the caller to determine heap or stack).
// This currently doesn't do sufficient error handling, which is a big
// TODO item.
bool
gcm_encrypt(gcm_ctx *ctx, gcm_str *in, gcm_str *out, int *error) {
  // This check ensures that we stop encrypting when
  // we hit the message send limit in MAX_MESSAGES.
  if (ctx->encrypt_limit) return false;

  // Basic sanity checks to prevent gross programmer error.
  // Generally, we expect the gcm_str data structures to
  // be set up properly when created.
  if (in->msg_length != out->msg_length) return false;
  if (!in->plaintext) return false;

  // Our first order of business is to set the 64 bits of IV that
  // is NOT the message counter (the message counter is incremented
  // every time we FINISH an encryption operation).
  // First, we fill the space w/ 64 random bits.
  //
  // Then, we XOR in our PID into the first 32 bits, and a high
  // resolution timer into the 2nd 32 bits.
  //
  // Finally, we copy the bytes out into the "noncelet" field in
  // the output string, so that they can be passed to the recipient,
  // as they are necessary for decrypting the message.
  //
  // A few things to note here:
  //
  // 1) We do not care about the byte order when we mix in fields.
  //    The only concern is whether the raw bytes in memory are laid
  //    out the same way in the client and in the server.  To that end,
  //    we load 32 bit values, but copy out the raw byte stream.
  // 2) We do NOT increment the message counter in the nonce until
  //    AFTER we encrypt the message (we count from 0 like any good
  //    programmer, and the counter starts 0'd out).  We end up not
  //    touching the last 32 bits of the IV here.
  // 3) We use the system call clock_getres() for timer info.  We
  //    ignore the seconds, and look at the nanoseconds.  On many
  //    machines this will be a 64-bit counter.  Since we store in 32
  //    bits, we definitely want to use the lowest 32 bits first.  The
  //    impact of this mechanism in the case of a VM resumption is
  //    dependent on the fidelity of the clock.  We win as long as two
  //    VMs don't end up with the same low 32-bits.  The odds of that
  //    kind of collision can vary.  However, it's important to
  //    remember that this is a fallback for a catastrophic failure in
  //    system randomness that we hope is already unlikely to happen.
  
  getrandom((void *)ctx->encr_iv.u.ints, 8, 0);

  struct timespec now;
  uint32_t        nanoseconds;
  
  clock_gettime(CLOCK_BOOTTIME, &now);

  // This ensures we portably get the lower 32 bits, no matter
  // how big a long is.
  nanoseconds = (uint32_t)((uint64_t)now.tv_nsec) & MASK_LOWER_32;
  ctx->encr_iv.u.ints[GCM_HPT_IX] ^= nanoseconds;
  ctx->encr_iv.u.ints[GCM_PID_IX] ^= getpid();

  memcpy(out->noncelet, ctx->encr_iv.u.bytes, NONCELET_LEN);

  if (!gcm_send_kernel_msg(ctx, in, out, ALG_OP_ENCRYPT, error)) {
    return false;
  }

  // Finally, increment the sender nonce.
  uint32_t counter_word = ntohl(ctx->encr_iv.u.ints[GCM_MSG_CTR_IX]) + 1;
  if ((counter_word & MASK_CTR) >= MAX_MESSAGES) {
    ctx->encrypt_limit = true;
  }
  ctx->encr_iv.u.ints[GCM_MSG_CTR_IX] = htonl(counter_word);
  return true;
}

bool
gcm_decrypt(gcm_ctx *ctx, gcm_str *in, gcm_str *out, int *error) {
  // For decryption, the gcm_str object should have the nonce
  // set that was sent with the message.  We can ignore the first
  // 64 bits, and just sanity check the bottom word to ensure that
  // the message counter is lower than the previously seen message
  // counter.  We then store the message counter in the ctx object.

  
}

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
  gcm_ctx      ctx;
  gcm_str      in, out;
  int          err;
  char        *plaintext = "[AAD]This is a test.";
  char         outbuf[100];
  struct iovec invector[1], outvector[1];
  
  in.msg_length       = strlen(plaintext)-5;
  in.tag_length       = 16;
  in.aad_length       = 0;
  in.plaintext        = true;
  in.iov              = invector;
  invector->iov_base  = (void *)plaintext;
  invector->iov_len   = in.msg_length + in.aad_length;
  out.msg_length      = in.msg_length;
  out.tag_length      = 0;
  out.aad_length      = 0;
  out.plaintext       = false;
  out.iov             = outvector;
  outvector->iov_base = (void *)outbuf;
  outvector->iov_len  = out.msg_length;
  gcm_initialize(&key, ROLE_CLIENT, &ctx);
  if (gcm_encrypt   (&ctx, &in, &out, &err) == true) {
    printf("gcm_encrypt succeeded\n");
  } 
}








