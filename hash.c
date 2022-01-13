#include "sha512.h"

// This is the specification we need to pass to the kernel
// when we create a file descriptor, in order for writes
// to that descriptor to hash.
// I do not yet know if this automatically selects NI when
// available, or if we need to add the logic for that.
// That's a TODO item.
struct sockaddr_alg sha512_spec
    = {.salg_family = AF_ALG, .salg_type = "hash", .salg_name = "sha512"};

bool
sha512_initialize(sha512_ctx *ctx)
{
    ctx->listen_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (bind(ctx->listen_fd,
             (struct sockaddr *)&sha512_spec,
             sizeof(sha512_spec))
        < 0) {
        return false;
    }
    ctx->fd = accept(ctx->listen_fd, NULL, 0);
    if (ctx->fd < 0) {
        return false;
    }

    return true;
}

bool
sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len, int *error)
{
    if (send(ctx->fd, data, len, MSG_MORE) != len) {
        *error = errno;
        return false;
    }
    return true;
}

bool
sha512_final(sha512_ctx *ctx, sha512_tag *tag, int *error)
{
    if (recv(ctx->fd, tag->bytes, SHA512_TAG_LENGTH, 0) != SHA512_TAG_LENGTH) {
        *error = errno;
        return false;
    }
    return true;
}

bool
sha512(sha512_ctx    *ctx,
       const uint8_t *data,
       size_t         len,
       sha512_tag    *tag,
       int           *error)
{
    if (send(ctx->fd, data, len, 0) != len) {
        *error = errno;
        return false;
    }
    return sha512_final(ctx, tag, error);
}
