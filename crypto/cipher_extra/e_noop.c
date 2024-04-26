#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../fipsmodule/cipher/internal.h"
#include "../internal.h"

// These values work for ChaCha20-Poly1305, so they should work for our cipher
#define EVP_AEAD_NOOP_TAG_LEN 16
#define EVP_AEAD_NOOP_NONCE_LEN 12

static int aead_noop_init(EVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len,
                          size_t tag_len) {
  if (tag_len > EVP_AEAD_NOOP_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }
  ctx->tag_len = EVP_AEAD_NOOP_TAG_LEN;
  return 1;
}

static void aead_noop_cleanup(EVP_AEAD_CTX *ctx) {}

static int aead_noop_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                  uint8_t *out_tag, size_t *out_tag_len,
                                  size_t max_out_tag_len, const uint8_t *nonce,
                                  size_t nonce_len, const uint8_t *in,
                                  size_t in_len, const uint8_t *extra_in,
                                  size_t extra_in_len, const uint8_t *ad,
                                  size_t ad_len) {
  size_t tag_len = ctx->tag_len;

  if (extra_in_len + tag_len < tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  // max_out_tag_len must be sized to allow for the additional extra_in_len
  // bytes.
  if (max_out_tag_len < tag_len + extra_in_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVP_AEAD_NOOP_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  if (extra_in_len) {
    // extra_in may point to an additional plaintext input buffer if the cipher
    // supports it. If present, extra_in_len additional bytes of plaintext are
    // encrypted and authenticated, and the ciphertext is written (before the
    // tag) to out_tag.
    OPENSSL_memcpy(out_tag, extra_in, extra_in_len);
  }

  // Encrypts and authenticates in_len bytes from in and authenticates ad_len
  // bytes from ad. It writes in_len bytes of ciphertext to out and the
  // authentication tag to out_tag. Exactly in_len bytes are written to out, and
  // up to EVP_AEAD_max_overhead+extra_in_len bytes to out_tag.
  if (in != out) {
    OPENSSL_memcpy(out, in, in_len);
  }
  OPENSSL_memset(out_tag + extra_in_len, 42, tag_len);

  // On successful return, *out_tag_len is set to the actual number of bytes
  // written to out_tag.
  *out_tag_len = tag_len + extra_in_len;

  // It returns one on success and zero otherwise.
  return 1;
}

static int aead_noop_open_gather(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *in, size_t in_len,
                                 const uint8_t *in_tag, size_t in_tag_len,
                                 const uint8_t *ad, size_t ad_len) {
  // The length of nonce, nonce_len, must be equal to the result of
  // EVP_AEAD_nonce_length for this AEAD.
  if (nonce_len != EVP_AEAD_NOOP_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  if (in_tag_len != ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  // Decrypts and authenticates in_len bytes from in and authenticates ad_len
  // bytes from ad using in_tag_len bytes of authentication tag from in_tag.
  // If successful, it writes in_len bytes of plaintext to out.
  if (in != out) {
    OPENSSL_memcpy(out, in, in_len);
  }

  // It returns one on success and zero otherwise.
  return 1;
}

static const EVP_AEAD aead_noop = {
    32,                       // key len (same as ChaCha20-Poly1305)
    EVP_AEAD_NOOP_NONCE_LEN,  // nonce len
    EVP_AEAD_NOOP_TAG_LEN,    // overhead: maximum number of additional bytes
                              // added by the act of sealing data
    EVP_AEAD_NOOP_TAG_LEN,    // max tag length
    1,                        // seal_scatter_supports_extra_in

    aead_noop_init,
    NULL,  // init_with_direction
    aead_noop_cleanup,
    NULL,  // open
    aead_noop_seal_scatter,
    aead_noop_open_gather,
    NULL,  // get_iv
    NULL,  // tag_len
};

const EVP_AEAD *EVP_aead_noop(void) { return &aead_noop; }
