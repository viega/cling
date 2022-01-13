#include "encdec.h"

// This is the specification we need to pass to the kernel
// when we create a file descriptor, in order for writes
// to that descriptor to encrypt using GCM.
// I do not yet know if this automatically selects NI when
// available, or if we need to add the logic for that.
// That's a TODO item.
struct sockaddr_alg gcm_spec
    = {.salg_family = AF_ALG, .salg_type = "aead", .salg_name = "gcm(aes)"};

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
gcm_init_ivs(gcm_ctx *ctx, int role)
{
    // Zero out the IV structures.
    memset(&(ctx->encr_iv), 0, sizeof(gcm_iv_t));
    memset(&(ctx->decr_iv), 0, sizeof(gcm_iv_t));
    // IV length is always 12.
    ctx->encr_iv.ivlen = GCM_IV_LEN;
    ctx->decr_iv.ivlen = GCM_IV_LEN;
    // Set the flag indicating which nonce is for server-originated
    // messages.  This flag is in the most significant byte of the final
    // 32 bits, which is otherwise occupied by the message counter,
    // which starts out at 0.
    if (role == ROLE_CLIENT) {
        IV_SET_CTR_WORD(ctx->encr_iv, F_CLIENT_ORIGIN);
        IV_SET_CTR_WORD(ctx->decr_iv, F_SERVER_ORIGIN);
    }
    else {
        IV_SET_CTR_WORD(ctx->encr_iv, F_SERVER_ORIGIN);
        IV_SET_CTR_WORD(ctx->decr_iv, F_CLIENT_ORIGIN);
    }
}

// This function is used to key a gcm_ctx, and set up its internal
// state.  It's meant to be used for new sessions with unique session
// keys.  If we eventually add the ability to resume sessions (after
// the process on either side dies), then we will have a different API
// for the state load / resumption.
//
// Realistically, none of these calls should fail as long as the code
// is running on a proper kernel, or if the system runs out of file
// descriptors.  If it's not working on an idle machine, the former is
// suspect.  Otherwise, it's the later.  Therefore, we don't worry
// about specific error codes, and just return success or failure.
//
// @param ctx  The context object to initialize.
// @param key  A 256-bit AES key.
// @param role Either ROLE_CLIENT or ROLE_SERVER
// @return true unless there's a kernel-level issue.
bool
gcm_initialize(gcm_ctx *ctx, aes_key_t *key, int32_t role)
{
    ctx->listen_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (bind(ctx->listen_fd, (struct sockaddr *)&gcm_spec, sizeof(gcm_spec))
        < 0) {
        return false;
    }
    if (setsockopt(ctx->listen_fd,
                   SOL_ALG,
                   ALG_SET_AEAD_AUTHSIZE,
                   NULL,
                   GCM_TAG_LEN)
        < 0) {
        return false;
    }
    if (setsockopt(ctx->listen_fd, SOL_ALG, ALG_SET_KEY, key->key, AES_KEYLEN)
        < 0) {
        return false;
    }
    ctx->fd = accept(ctx->listen_fd, NULL, 0);
    if (ctx->fd < 0) {
        return false;
    }
    gcm_init_ivs(ctx, role);
    ctx->origin_bit = (role == ROLE_SERVER) ? F_SERVER_ORIGIN : F_CLIENT_ORIGIN;
    ctx->encrypt_limit = false;
    return true;
}

// The kernel uses a pretty regular interface for encryption and
// decryption.  This code is used by both to perform the desired
// operation, and read the result.
static bool
gcm_send_kernel_msg(gcm_ctx *ctx, gcm_str *str, uint32_t operation, int *error)
{
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
    struct msghdr msg = {
        0,
    };
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
    int mbuf_len = CMSG_SPACE(sizeof(uint32_t)) + // operation
                   CMSG_SPACE(sizeof(gcm_iv_t)) + // IV
                   CMSG_SPACE(sizeof(uint32_t));  // AAD len
    uint8_t mbuf[mbuf_len];

    memset(mbuf, 0, mbuf_len);

    msg.msg_control    = (void *)mbuf;
    msg.msg_controllen = mbuf_len;
    // Note that IOV stands for "IO vector", meaning we can send in an
    // array of items that point to strings, for the kernel to treat as
    // a consecutive message.  For right now, we will just one-shot
    // encrypt from a single buffer.
    msg.msg_iov        = str->in_iov;
    msg.msg_iovlen     = str->iov_count;

    // Here, we're using the kernel's APIs for adding metadata to our
    // message.
    header                         = CMSG_FIRSTHDR(&msg);
    header->cmsg_level             = SOL_ALG;
    header->cmsg_type              = ALG_SET_OP;
    header->cmsg_len               = CMSG_LEN(sizeof(uint32_t));
    // We can't just reference a cmsg_data field, it needs to be computed.
    *(uint32_t *)CMSG_DATA(header) = operation;

    header             = CMSG_NXTHDR(&msg, header);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type  = ALG_SET_IV;
    header->cmsg_len   = CMSG_SPACE(sizeof(gcm_iv_t));
    memcpy(CMSG_DATA(header), &str->iv, sizeof(gcm_iv_t));

    // This needs to be sent, even if there is no AAD.
    header                         = CMSG_NXTHDR(&msg, header);
    header->cmsg_level             = SOL_ALG;
    header->cmsg_type              = ALG_SET_AEAD_ASSOCLEN;
    header->cmsg_len               = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(header) = str->aad_length;

    if (sendmsg(ctx->fd, &msg, 0) < 0) {
        *error = errno;
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

    uint32_t outlen = str->msg_length;
    ssize_t  n;
    uint8_t *outptr;

    if (operation == ALG_OP_ENCRYPT) {
        outlen += GCM_TAG_LEN;
    }
    outptr = str->out_iov->iov_base;

    while (outlen) {
        n = read(ctx->fd, outptr, outlen);
        if (n > 0) {
            outptr += n;
            outlen -= n;
        }
        else {
            if (errno != EINTR) {
                *error = errno;
                return false;
            }
        }
    }

    return true;
}

// @param ctx       The gcm context to use for encrypting.
// @param str       A gcm_str object that holds both the input and the output.
// @param error     Error code, if appropriate
// @return true if successful, false if error.
bool
gcm_encrypt(gcm_ctx *ctx, gcm_str *str, int *error)
{
    *error = 0;

    // This check ensures that we stop encrypting when we hit the
    // message send limit in MAX_MESSAGES.
    if (ctx->encrypt_limit) {
        *error = ERR_ENCRYPT_LIMIT;
        return false;
    }

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

    if (getrandom((void *)ctx->encr_iv.u.ints, 8, 0) == -1) {
        *error = errno;
        return false;
    }

    struct timespec now;
    uint32_t        nanoseconds;

    if (clock_gettime(CLOCK_BOOTTIME, &now) == -1) {
        *error = errno;
        return false;
    }

    // This ensures we portably get the lower 32 bits, no matter
    // how big a long is.
    nanoseconds = (uint32_t)((uint64_t)now.tv_nsec) & MASK_LOWER_32;
    ctx->encr_iv.u.ints[GCM_HPT_IX] ^= nanoseconds;
    ctx->encr_iv.u.ints[GCM_PID_IX] ^= getpid();

    // We store the nonce in both the ctx object and the str object.
    memcpy(&str->iv, &ctx->encr_iv, sizeof(gcm_iv_t));

    if (!gcm_send_kernel_msg(ctx, str, ALG_OP_ENCRYPT, error)) {
        return false;
    }

    // Finally, increment the sender IV in the context object,
    // prepping it for the next message.  Don't touch the IV in the
    // str object, it should be set to the IV used for encryption.
    uint32_t counter_word = IV_GET_CTR_WORD(ctx->encr_iv) + 1;
    if ((counter_word & MASK_CTR) >= MAX_MESSAGES) {
        ctx->encrypt_limit = true;
    }
    IV_SET_CTR_WORD(ctx->encr_iv, counter_word);
    return true;
}

// @param ctx The context object.
// @param str The gcm_str object for this operation.
// @param error Holds any error code.
// @return true if successful, false if there's an error.
bool
gcm_decrypt(gcm_ctx *ctx, gcm_str *str, int *error)
{
    *error = 0;

    // For decryption, the gcm_str input object should have the nonce
    // set that was sent with the message.  In terms of validating the
    // nonce, we can ignore the first 64 bits, and just sanity check the
    // bottom word to ensure that the message counter is lower than the
    // previously seen message counter.  We then store the message
    // counter in the ctx object.

    // Counter received in IV w/ plaintext.  Note that both of these
    // should be directly comparable, already in host byte order.
    uint32_t rcv_ctr = IV_GET_CTR_WORD(str->iv) & MASK_CTR;
    // The minimum acceptable counter value, based on last decrypted msg.
    uint32_t min_ctr = IV_GET_CTR_WORD(ctx->decr_iv) & MASK_CTR;
    if (rcv_ctr < min_ctr) {
        *error = ERR_BAD_PLAINTEXT;
        return false; // A previously seen sequence ID.
    }

    // This XOR operation compares the server origin bit in the counter
    // word to this GCM context's stored origin bit.  They should
    // be DIFFERENT-- if we're the client, the inbound message should
    // have the server origin bit set.  If we're the server, the inbound
    // message should not have the bit set.
    if (!(IV_GET_ORIGIN(str->iv) ^ ctx->origin_bit)) {
        *error = ERR_BAD_ORIGIN;
        return false;
    }

    // At this point, the nonce has passed muster, so let's decrypt.
    if (!gcm_send_kernel_msg(ctx, str, ALG_OP_DECRYPT, error)) {
        return false;
    }
    // Finally, we update the decryption nonce in the ctx object.
    // It should be one higher than the counter seen in the message.
    uint32_t counter_word = IV_GET_CTR_WORD(str->iv) + 1;
    IV_SET_CTR_WORD(ctx->decr_iv, counter_word);
    return true;
}
