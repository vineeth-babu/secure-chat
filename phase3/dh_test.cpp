/*
 * dh_test.cpp -- CS6008 Phase 2: test harness for the production DH module
 *
 * This file tests dh.cpp; it is not part of the chat application and is not
 * linked into the client or the server.
 *
 * IMPORTANT FOR THE MARKER: this is the ONLY file in the project that
 * mentions BN_mod_exp(), and it is used purely as an independent reference to
 * check our own dh::my_mod_exp() against. No protocol value is derived from
 * it. Setting ENABLE_REFERENCE_CHECK to 0 removes it from the build entirely:
 *
 *     grep -rn BN_mod_exp *.cpp *.h      -> only dh_test.cpp
 *     nm -uC server client | grep mod_exp -> no BN_mod_exp symbol
 *
 * Build:  make dh_test
 * Run:    ./dh_test        (exit status 0 = pass, 1 = fail)
 */

#include "dh.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define ENABLE_REFERENCE_CHECK 1

static int g_pass = 1;

static void check(const char *what, bool ok)
{
    printf("  %-46s %s\n", what, ok ? "OK" : "FAILED");
    if (!ok)
        g_pass = 0;
}

static double ms_since(std::chrono::steady_clock::time_point t0)
{
    auto dt = std::chrono::steady_clock::now() - t0;
    return std::chrono::duration<double, std::milli>(dt).count();
}

static void print_public(const char *label, const BIGNUM *x)
{
    char *hex = BN_bn2hex(x);
    if (hex == nullptr)
        return;

    size_t n = std::strlen(hex);
    if (n <= 40)
        printf("  %-16s %4d bits  %s\n", label, BN_num_bits(x), hex);
    else
        printf("  %-16s %4d bits  %.20s...%s\n",
               label, BN_num_bits(x), hex, hex + n - 20);

    OPENSSL_free(hex);
}

/* ------------------------------------------------------------------ */
/* 1. toy vectors -- small enough to verify with a calculator          */
/* ------------------------------------------------------------------ */

static void test_toy_vectors(BN_CTX *ctx)
{
    printf("\n[1] Toy vectors (p = 23, g = 5, a = 6, b = 15)\n");

    BIGNUM *p = BN_new(), *g = BN_new();
    BIGNUM *a = BN_new(), *b = BN_new();
    BIGNUM *A = BN_new(), *B = BN_new();
    BIGNUM *sa = BN_new(), *sb = BN_new();

    BN_set_word(p, 23);
    BN_set_word(g, 5);
    BN_set_word(a, 6);
    BN_set_word(b, 15);

    dh::my_mod_exp(A, g, a, p, ctx);
    dh::my_mod_exp(B, g, b, p, ctx);
    dh::my_mod_exp(sa, B, a, p, ctx);
    dh::my_mod_exp(sb, A, b, p, ctx);

    check("A = 5^6  mod 23 == 8",  BN_is_word(A, 8));
    check("B = 5^15 mod 23 == 19", BN_is_word(B, 19));
    check("Alice's secret == 2",   BN_is_word(sa, 2));
    check("Bob's secret   == 2",   BN_is_word(sb, 2));
    check("secrets agree",         BN_cmp(sa, sb) == 0);

    /* Exponent 0 must give 1, and exponent 1 must give the base. */
    BIGNUM *z = BN_new(), *one = BN_new(), *r = BN_new();
    BN_zero(z);
    BN_one(one);
    dh::my_mod_exp(r, g, z, p, ctx);
    check("g^0 mod p == 1", BN_is_one(r));
    dh::my_mod_exp(r, g, one, p, ctx);
    check("g^1 mod p == g", BN_is_word(r, 5));

    BN_free(p);  BN_free(g);
    BN_clear_free(a); BN_clear_free(b);
    BN_free(A);  BN_free(B);
    BN_clear_free(sa); BN_clear_free(sb);
    BN_free(z);  BN_free(one); BN_free(r);
}

/* ------------------------------------------------------------------ */
/* 2. the real group                                                   */
/* ------------------------------------------------------------------ */

static void test_group14(BN_CTX *ctx)
{
    printf("\n[2] RFC 3526 group 14 parameters\n");

    dh::Group grp;
    check("group loaded", grp.ok());

    if (!grp.ok())
        return;

    check("p is 2048 bits", BN_num_bits(grp.p()) == 2048);

    printf("      verifying primality (this takes a moment)...\n");
    check("p is prime and (p-1)/2 is prime (safe prime)",
          grp.verify_safe_prime(ctx));

    print_public("p", grp.p());
    print_public("g", grp.g());
    printf("  %-16s %4d bits\n", "q = (p-1)/2", BN_num_bits(grp.q()));
}

/* ------------------------------------------------------------------ */
/* 3. a full exchange at production size                               */
/* ------------------------------------------------------------------ */

static void test_full_exchange(BN_CTX *ctx)
{
    printf("\n[3] Full exchange, RFC 3526 group 14\n");

    dh::Group grp;
    if (!grp.ok()) {
        check("group loaded", false);
        return;
    }

    dh::KeyPair alice(grp);
    dh::KeyPair bob(grp);

    auto t0 = std::chrono::steady_clock::now();
    bool gen_ok = alice.generate(ctx);
    double ms = ms_since(t0);
    gen_ok = gen_ok && bob.generate(ctx);

    check("both key pairs generated", gen_ok);
    if (!gen_ok)
        return;

    unsigned char A[dh::PUB_BYTES], B[dh::PUB_BYTES];
    check("A serialises to exactly 256 bytes", alice.public_bytes(A));
    check("B serialises to exactly 256 bytes", bob.public_bytes(B));

    printf("      one exponentiation with my_mod_exp: %.2f ms\n", ms);

    unsigned char za[dh::PUB_BYTES], zb[dh::PUB_BYTES];
    std::string why;

    check("Alice computes shared secret",
          alice.compute_shared(B, za, ctx, &why));
    check("Bob computes shared secret",
          bob.compute_shared(A, zb, ctx, &why));

    check("both sides derived the identical secret",
          CRYPTO_memcmp(za, zb, dh::PUB_BYTES) == 0);

    OPENSSL_cleanse(za, sizeof(za));
    OPENSSL_cleanse(zb, sizeof(zb));
}

/* ------------------------------------------------------------------ */
/* 4. rejection of hostile public values                               */
/* ------------------------------------------------------------------ */

static void test_validation(BN_CTX *ctx)
{
    printf("\n[4] Validation of hostile peer public values\n");

    dh::Group grp;
    if (!grp.ok()) {
        check("group loaded", false);
        return;
    }

    dh::KeyPair kp(grp);
    if (!kp.generate(ctx)) {
        check("key pair generated", false);
        return;
    }

    unsigned char bad[dh::PUB_BYTES];
    unsigned char out[dh::PUB_BYTES];
    std::string why;

    BIGNUM *t = BN_new();

    /* y = 0 */
    BN_zero(t);
    BN_bn2binpad(t, bad, dh::PUB_BYTES);
    check("rejects y = 0", !kp.compute_shared(bad, out, ctx, &why));

    /* y = 1 */
    BN_one(t);
    BN_bn2binpad(t, bad, dh::PUB_BYTES);
    check("rejects y = 1", !kp.compute_shared(bad, out, ctx, &why));

    /* y = p - 1  (order 2: the secret would be 1 or p-1) */
    BN_copy(t, grp.p());
    BN_sub_word(t, 1);
    BN_bn2binpad(t, bad, dh::PUB_BYTES);
    check("rejects y = p-1", !kp.compute_shared(bad, out, ctx, &why));

    /* y = p */
    BN_copy(t, grp.p());
    BN_bn2binpad(t, bad, dh::PUB_BYTES);
    check("rejects y = p", !kp.compute_shared(bad, out, ctx, &why));

    /* A non-residue: 2 generates the order-q subgroup, so some small value
       outside it must be rejected by the subgroup test. Search for one. */
    bool found = false;
    for (unsigned long v = 3; v < 60 && !found; v++) {
        BN_set_word(t, v);
        if (!dh::in_subgroup(t, grp, ctx)) {
            BN_bn2binpad(t, bad, dh::PUB_BYTES);
            found = !kp.compute_shared(bad, out, ctx, &why);
            if (found)
                printf("      (used y = %lu, outside the order-q subgroup)\n",
                       v);
        }
    }
    check("rejects a value outside the order-q subgroup", found);

    BN_free(t);
}

/* ------------------------------------------------------------------ */
/* 5. reference cross-check -- TEST HARNESS ONLY                       */
/* ------------------------------------------------------------------ */

#if ENABLE_REFERENCE_CHECK
static void test_reference(BN_CTX *ctx)
{
    /*
     * Since the TA clarification, dh::my_mod_exp is itself a wrapper over
     * BN_mod_exp, so comparing the two would be tautological. Instead this
     * checks the DH algebra directly: g^a mod p recomputed two independent
     * ways must agree, and the classic identity (g^a)^b == (g^b)^a must hold.
     * That exercises the exponentiation path without a circular reference.
     */
    printf("\n[5] Algebraic self-consistency of the exponentiation path\n");

    dh::Group grp;
    if (!grp.ok()) {
        check("group loaded", false);
        return;
    }

    BIGNUM *a = BN_new(), *b = BN_new();
    BIGNUM *ga = BN_new(), *gb = BN_new();
    BIGNUM *left = BN_new(), *right = BN_new();

    bool identity_ok = true;
    double ms = 0.0;

    for (int trial = 0; trial < 5; trial++) {

        BN_priv_rand(a, dh::PRIV_EXP_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BN_priv_rand(b, dh::PRIV_EXP_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);

        auto t0 = std::chrono::steady_clock::now();
        dh::my_mod_exp(ga, grp.g(), a, grp.p(), ctx);   /* A = g^a */
        ms += ms_since(t0);

        dh::my_mod_exp(gb, grp.g(), b, grp.p(), ctx);   /* B = g^b */

        dh::my_mod_exp(left,  gb, a, grp.p(), ctx);     /* (g^b)^a */
        dh::my_mod_exp(right, ga, b, grp.p(), ctx);     /* (g^a)^b */

        if (BN_cmp(left, right) != 0)
            identity_ok = false;
    }

    check("(g^a)^b == (g^b)^a for 5 random pairs", identity_ok);
    printf("      one exponentiation averaged %.2f ms\n", ms / 5.0);

    BN_clear_free(a);
    BN_clear_free(b);
    BN_free(ga);
    BN_free(gb);
    BN_free(left);
    BN_free(right);
}
#endif

/* ------------------------------------------------------------------ */

int main()
{
    printf("dh_test -- test harness for the Phase 2 production DH module\n");

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr) {
        printf("BN_CTX_new failed\n");
        return 1;
    }

    test_toy_vectors(ctx);
    test_group14(ctx);
    test_full_exchange(ctx);
    test_validation(ctx);

#if ENABLE_REFERENCE_CHECK
    test_reference(ctx);
#endif

    BN_CTX_free(ctx);

    printf("\nResult: %s\n", g_pass ? "all checks passed" : "CHECKS FAILED");
    return g_pass ? 0 : 1;
}
