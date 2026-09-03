/*
 * crypto.h -- key derivation and the AES-256-GCM record layer
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace crypto {

constexpr size_t KEY_BYTES   = 32;   /* AES-256                       */
constexpr size_t TAG_BYTES   = 16;   /* GCM tag                       */
constexpr size_t NONCE_BYTES = 12;   /* 96-bit GCM nonce -- this is GCM's
                                        native size; any other length
                                        forces an extra GHASH step */

/* Largest application message we'll send or accept -- matches the
   4096-byte line cap from the plaintext chat version. */
constexpr size_t MAX_PLAINTEXT = 4096;

/* Record on the wire:
 *
 *   [4 bytes  body length, big-endian ]
 *   [8 bytes  counter, big-endian     ]  <-+ body
 *   [n bytes  ciphertext              ]    |
 *   [16 bytes GCM tag                 ]  <-+
 *
 * body length = 8 + n + 16, so it is bounded and can be validated before a
 * single byte is allocated.
 */
constexpr size_t HDR_BYTES      = 4;
constexpr size_t CTR_BYTES      = 8;
constexpr size_t MIN_BODY_BYTES = CTR_BYTES + TAG_BYTES;
constexpr size_t MAX_BODY_BYTES = CTR_BYTES + MAX_PLAINTEXT + TAG_BYTES;

enum class Role { Client, Server };

enum class RecvResult {
    Ok,
    Closed,         /* clean EOF / peer hung up                        */
    AuthFailure,    /* GCM tag did not verify -- tampering or replay   */
    ProtocolError   /* malformed framing, bad length, counter mismatch */
};

// key derivation

/*
 * key = SHA-256( "CS6008-P2-KEY-v1" || Z )
 *
 * Z is the raw DH shared secret, serialised to a fixed 256 bytes.
 *
 * Why hash instead of using Z directly: Z is an element of a subgroup of
 * Z*_p, not a uniformly random 256-bit string, and it carries algebraic
 * structure tied back to g^ab. SHA-256 compresses it to the right size and
 * destroys that structure, giving something that looks like a random key.
 *
 * The label gives domain separation -- a different label over the same Z
 * gives an unrelated output, which is what makes the fingerprint below safe
 * to print, and lets later phases derive other keys from the same exchange.
 */
void derive_key(const unsigned char *shared, size_t shared_len,
                unsigned char key_out[KEY_BYTES]);

/*
 * fingerprint = first 8 bytes of SHA-256( "CS6008-P2-FP-v1" || key ),
 * formatted as hex.
 *
 * Safe to print: different label than the KDF, so it's a one-way function
 * of the key that reveals neither the key nor Z. Both sides print it so we
 * can visually confirm they agreed on the same key.
 */
std::string fingerprint(const unsigned char key[KEY_BYTES]);

// the encrypted record channel

class SecureChannel {
public:
    SecureChannel();
    ~SecureChannel();

    SecureChannel(const SecureChannel &) = delete;
    SecureChannel &operator=(const SecureChannel &) = delete;

    /*
     * Installs the derived key. Role picks the direction tags used to build
     * nonces, so both directions can share one key without ever sharing a
     * nonce:
     *
     *   nonce = [4-byte direction tag][8-byte counter]   (96 bits total)
     *
     * Client sends on tag 1, receives on tag 2; server is the mirror image.
     * Counters start at 0 and go up by one per record, so a (key, nonce)
     * pair is never reused -- reusing one is the one thing that actually
     * breaks GCM.
     */
    void init(const unsigned char key[KEY_BYTES], Role role);

    /* Encrypts and sends one message. Thread-safe -- the send counter is
       behind a mutex because on the server, one thread might relay a
       message to a client while that client's own thread also wants to
       send something. */
    bool send_msg(int fd, const std::string &plaintext);

    /* Receives, verifies and decrypts one message. Only ever called from
       one reader thread per connection, so the receive counter doesn't need
       a lock. */
    RecvResult recv_msg(int fd, std::string &plaintext_out);

private:
    unsigned char key_[KEY_BYTES];
    uint32_t send_dir_;
    uint32_t recv_dir_;
    uint64_t send_ctr_;
    uint64_t recv_ctr_;
    bool ready_;
    std::mutex send_mtx_;
};

}  /* namespace crypto */

#endif /* CRYPTO_H */
