#include "dh.h"
#include "net.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <arpa/inet.h>

#include <cstring>
#include <cstdint>

namespace dh {

static const char *MODP2048_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

static const unsigned long MODP2048_G = 2;


// Calculate base^exp mod m using OpenSSL's big number operation
bool my_mod_exp(BIGNUM *out, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *m, BN_CTX *ctx)
{
    BIGNUM *e = BN_dup(exp);
    if (e == nullptr)
        return false;

    // Use the constant-time path for the exponent
    BN_set_flags(e, BN_FLG_CONSTTIME);

    int rc = BN_mod_exp(out, base, e, m, ctx);

    BN_clear_free(e);
    return rc == 1;
}


// Load the RFC 3526 Group 14 parameters
Group::Group() : p_(nullptr), g_(nullptr), q_(nullptr), ok_(false)
{
    g_ = BN_new();
    q_ = BN_new();
    if (g_ == nullptr || q_ == nullptr)
        return;

    int consumed = BN_hex2bn(&p_, MODP2048_HEX);
    if (p_ == nullptr ||
        consumed != static_cast<int>(std::strlen(MODP2048_HEX)))
        return;

    if (BN_num_bits(p_) != 2048)
        return;

    if (!BN_set_word(g_, MODP2048_G))
        return;

    // q = (p - 1) / 2
    if (!BN_copy(q_, p_) || !BN_sub_word(q_, 1) || !BN_rshift1(q_, q_))
        return;

    ok_ = true;
}

Group::~Group()
{
    BN_free(p_);
    BN_free(g_);
    BN_free(q_);
}


// Check that both p and q are prime
bool Group::verify_safe_prime(BN_CTX *ctx) const
{
    if (!ok_)
        return false;

    if (BN_check_prime(p_, ctx, nullptr) != 1)
        return false;
    if (BN_check_prime(q_, ctx, nullptr) != 1)
        return false;

    return true;
}


// Check that the public value is within the valid range
bool in_range(const BIGNUM *y, const Group &grp)
{
    BIGNUM *pm1 = BN_new();
    if (pm1 == nullptr)
        return false;

    bool ok = false;

    if (BN_copy(pm1, grp.p()) && BN_sub_word(pm1, 1)) {
        // Valid values satisfy 1 < y < p - 1
        ok = (BN_cmp(y, BN_value_one()) > 0) && (BN_cmp(y, pm1) < 0);
    }

    BN_free(pm1);
    return ok;
}


// Check whether the public value belongs to the expected subgroup
bool in_subgroup(const BIGNUM *y, const Group &grp, BN_CTX *ctx)
{
    BIGNUM *t = BN_new();
    if (t == nullptr)
        return false;

    bool ok = false;

    if (my_mod_exp(t, y, grp.q(), grp.p(), ctx))
        ok = BN_is_one(t);

    BN_free(t);
    return ok;
}


KeyPair::KeyPair(const Group &grp)
    : grp_(grp), priv_(BN_new()), pub_(BN_new())
{
}

KeyPair::~KeyPair()
{
    // Clear private values before releasing memory
    BN_clear_free(priv_);
    BN_clear_free(pub_);
}


// Generate a private exponent and the corresponding public value
bool KeyPair::generate(BN_CTX *ctx)
{
    if (priv_ == nullptr || pub_ == nullptr || !grp_.ok())
        return false;

    if (RAND_status() != 1)
        return false;

    if (!BN_priv_rand(priv_, PRIV_EXP_BITS,
                      BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        return false;

    if (BN_num_bits(priv_) != PRIV_EXP_BITS)
        return false;

    // A = g^a mod p
    return my_mod_exp(pub_, grp_.g(), priv_, grp_.p(), ctx);
}


// Convert the public value into a fixed-size byte array
bool KeyPair::public_bytes(unsigned char out[PUB_BYTES]) const
{
    if (pub_ == nullptr)
        return false;

    return BN_bn2binpad(pub_, out, PUB_BYTES) == static_cast<int>(PUB_BYTES);
}


// Calculate the shared secret using the peer's public value
bool KeyPair::compute_shared(const unsigned char peer[PUB_BYTES],
                             unsigned char out[PUB_BYTES],
                             BN_CTX *ctx,
                             std::string *why) const
{
    bool ok = false;

    BIGNUM *y = BN_bin2bn(peer, PUB_BYTES, nullptr);
    BIGNUM *z = BN_new();

    if (y == nullptr || z == nullptr) {
        if (why) *why = "out of memory";
        goto done;
    }

    // Validate the received public value before using it
    if (!in_range(y, grp_)) {
        if (why) *why = "peer public value out of range (must satisfy 1 < y < p-1)";
        goto done;
    }

    if (!in_subgroup(y, grp_, ctx)) {
        if (why) *why = "peer public value is not in the order-q subgroup";
        goto done;
    }

    // Z = y^a mod p
    if (!my_mod_exp(z, y, priv_, grp_.p(), ctx)) {
        if (why) *why = "modular exponentiation failed";
        goto done;
    }

    if (BN_is_zero(z) || BN_is_one(z)) {
        if (why) *why = "degenerate shared secret";
        goto done;
    }

    if (BN_bn2binpad(z, out, PUB_BYTES) != static_cast<int>(PUB_BYTES)) {
        if (why) *why = "failed to serialise shared secret";
        goto done;
    }

    ok = true;

done:
    BN_free(y);
    BN_clear_free(z);
    return ok;
}


// Perform the Diffie-Hellman exchange over the socket
bool run_handshake(int fd, unsigned char shared_out[PUB_BYTES],
                   std::string *why)
{
    Group grp;
    if (!grp.ok()) {
        if (why) *why = "failed to load RFC 3526 group 14 parameters";
        return false;
    }

    // Each handshake uses its own BN_CTX
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr) {
        if (why) *why = "BN_CTX_new failed";
        return false;
    }

    bool ok = false;
    unsigned char mine[PUB_BYTES];
    unsigned char peer[PUB_BYTES];
    uint32_t netlen = 0;

    {
        KeyPair kp(grp);

        if (!kp.generate(ctx)) {
            if (why) *why = "failed to generate DH key pair";
            goto done;
        }

        if (!kp.public_bytes(mine)) {
            if (why) *why = "failed to serialise our public value";
            goto done;
        }

        // Send our public value with its length
        netlen = htonl(static_cast<uint32_t>(PUB_BYTES));
        if (!net::write_all(fd, &netlen, sizeof(netlen)) ||
            !net::write_all(fd, mine, PUB_BYTES)) {
            if (why) *why = "failed to send our DH public value";
            goto done;
        }

        // Read the peer's public value
        if (!net::read_exact(fd, &netlen, sizeof(netlen))) {
            if (why) *why = "connection closed during DH exchange";
            goto done;
        }

        if (ntohl(netlen) != PUB_BYTES) {
            if (why) *why = "peer sent a DH public value of the wrong length";
            goto done;
        }

        if (!net::read_exact(fd, peer, PUB_BYTES)) {
            if (why) *why = "connection closed while reading peer DH value";
            goto done;
        }

        // Reject a reflected copy of our own public value
        if (CRYPTO_memcmp(peer, mine, PUB_BYTES) == 0) {
            if (why) *why = "peer reflected our own public value";
            goto done;
        }

        if (!kp.compute_shared(peer, shared_out, ctx, why))
            goto done;

        ok = true;
    }

done:
    OPENSSL_cleanse(mine, sizeof(mine));
    OPENSSL_cleanse(peer, sizeof(peer));
    BN_CTX_free(ctx);
    return ok;
}

}  // namespace dh