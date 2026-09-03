/*
 * crypto.h -- CS6008 Phase 2: key derivation and the AES-256-GCM record layer
 *
 * Assignment constraints (§1.2, §3.1):
 *   - Only low-level primitives are used: <openssl/evp.h> for AES-GCM and
 *     SHA-256. No TLS/SSL, no DH/ECDH, no EVP_PKEY key agreement.
 *   - The raw DH shared secret is never used directly as a key; it is hashed
 *     (see derive_key).
 *   - Authenticated encryption: a record whose tag does not verify is never
 *     turned into plaintext, and the caller aborts the connection.
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
constexpr size_t NONCE_BYTES = 12;   /* 96-bit GCM nonce (the native  */
                                     /* size; anything else forces an */
                                     /* extra GHASH step)             */

/* Largest application message we will send or accept. Matches the 4096-byte
   line cap the Phase 1 code already enforced. */
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

/* --------------------------------------------------------------- */
/* Key derivation                                                   */
/* --------------------------------------------------------------- */

/*
 * key = SHA-256( "CS6008-P2-KEY-v1" || Z )
 *
 * Z is the raw DH shared secret, serialised to a fixed 256 bytes.
 *
 * Why hash at all (assignment §3.1): Z is a uniformly-random-looking but not
 * uniform element of a subgroup of Z*_p. It is 2048 bits when we need 256,
 * it is not uniformly distributed over its range, and it carries algebraic
 * structure -- partial information about Z relates back to g^ab. SHA-256
 * acts as a randomness extractor: it compresses to exactly the key length,
 * destroys the algebraic relationship to g, and yields something
 * computationally indistinguishable from a uniform 256-bit string.
 *
 * The label provides domain separation, so a different label over the same Z
 * yields an unrelated value -- which is how the fingerprint below is made
 * safe, and how Phase 4/5 will derive further keys from one exchange.
 */
void derive_key(const unsigned char *shared, size_t shared_len,
                unsigned char key_out[KEY_BYTES]);

/*
 * fingerprint = first 8 bytes of SHA-256( "CS6008-P2-FP-v1" || key ),
 * formatted as hex.
 *
 * Safe to print: the label differs from the KDF label, so this is a
 * one-way function of the key that reveals neither the key nor Z. Both
 * sides print it to demonstrate agreement (assignment §3.2).
 */
std::string fingerprint(const unsigned char key[KEY_BYTES]);

/* --------------------------------------------------------------- */
/* The encrypted record channel                                     */
/* --------------------------------------------------------------- */

class SecureChannel {
public:
    SecureChannel();
    ~SecureChannel();

    SecureChannel(const SecureChannel &) = delete;
    SecureChannel &operator=(const SecureChannel &) = delete;

    /*
     * Install the derived key. Role selects the direction tags used to build
     * nonces, so the two directions never share a nonce even though they
     * share a key:
     *
     *   nonce = [4-byte direction tag][8-byte counter]   (96 bits total)
     *
     * Client sends with tag 1 and receives on tag 2; the server is the
     * mirror image. Counters start at 0 and increment once per record, so a
     * (key, nonce) pair is never reused -- the one failure mode that would
     * break GCM outright.
     */
    void init(const unsigned char key[KEY_BYTES], Role role);

    /* Encrypt and send one application message. Thread-safe: the send
       counter is protected by a mutex, because on the server one thread may
       relay a message to a client while that client's own thread is sending
       it a response. */
    bool send_msg(int fd, const std::string &plaintext);

    /* Receive, verify and decrypt one application message. Only called from
       a single reader thread per connection, so the receive counter needs no
       lock. Returns Ok / Closed / AuthFailure / ProtocolError. */
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
