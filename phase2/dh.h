#ifndef DH_H
#define DH_H

#include <openssl/bn.h>

#include <cstddef>
#include <string>

namespace dh {

// 2048-bit values are stored using 256 bytes
constexpr size_t PUB_BYTES = 256;

// Size of the private exponent
constexpr int PRIV_EXP_BITS = 320;


// Calculate out = base^exp mod m
bool my_mod_exp(BIGNUM *out, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *m, BN_CTX *ctx);


// Diffie-Hellman group parameters
class Group {
public:
    Group();
    ~Group();

    Group(const Group &) = delete;
    Group &operator=(const Group &) = delete;

    bool ok() const { return ok_; }

    const BIGNUM *p() const { return p_; }
    const BIGNUM *g() const { return g_; }
    const BIGNUM *q() const { return q_; }

    // Check that p and q are prime
    bool verify_safe_prime(BN_CTX *ctx) const;

private:
    BIGNUM *p_;
    BIGNUM *g_;
    BIGNUM *q_;
    bool ok_;
};


// Check whether a received public value is in the valid range
bool in_range(const BIGNUM *y, const Group &grp);

// Check whether a received public value belongs to the correct subgroup
bool in_subgroup(const BIGNUM *y, const Group &grp, BN_CTX *ctx);


// Stores the private and public values for one DH exchange
class KeyPair {
public:
    explicit KeyPair(const Group &grp);
    ~KeyPair();

    KeyPair(const KeyPair &) = delete;
    KeyPair &operator=(const KeyPair &) = delete;

    // Generate a private exponent and calculate the public value
    bool generate(BN_CTX *ctx);

    // Convert the public value to a fixed-size byte array
    bool public_bytes(unsigned char out[PUB_BYTES]) const;

    // Validate the peer value and calculate the shared secret
    bool compute_shared(const unsigned char peer[PUB_BYTES],
                        unsigned char out[PUB_BYTES],
                        BN_CTX *ctx,
                        std::string *why) const;

private:
    const Group &grp_;
    BIGNUM *priv_;
    BIGNUM *pub_;
};


// Perform the complete DH exchange on an existing socket
bool run_handshake(int fd, unsigned char shared_out[PUB_BYTES],
                   std::string *why);

}  // namespace dh

#endif  // DH_H