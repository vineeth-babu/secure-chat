/*
 * e2e_test.cpp -- CS6008 Phase 4, Checkpoint 1 test harness
 *
 * Tests the e2e module in isolation: Base64 round-trip, AES-256-GCM
 * round-trip, and rejection of tampered ciphertext, tampered tags, tampered
 * nonces, truncation and malformed Base64.
 *
 * Build:  make e2e_test
 * Run:    ./e2e_test        (exit status 0 = pass, 1 = fail)
 */

#include "e2e.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_pass = 1;

/* A4: every RAND_bytes prerequisite must be checked. If the CSPRNG fails we
   must fail the test rather than continue with uninitialised memory. */
static bool rnd(unsigned char *buf, size_t len)
{
    return RAND_bytes(buf, static_cast<int>(len)) == 1;
}

static void check(const char *what, bool ok)
{
    std::printf("  %-58s %s\n", what, ok ? "OK" : "FAILED");
    if (!ok)
        g_pass = 0;
}

/* Flip one bit at a byte offset inside the decoded blob, then re-encode. */
static std::string tamper_at(const std::string &b64, size_t offset)
{
    std::vector<unsigned char> blob;
    if (!e2e::base64_decode(b64, blob) || offset >= blob.size())
        return std::string("!!decode-failed!!");
    blob[offset] ^= 0x01;
    return e2e::base64_encode(blob.data(), blob.size());
}

/* ------------------------------------------------------------------ */
/* 1. Base64                                                           */
/* ------------------------------------------------------------------ */

static void test_base64()
{
    std::printf("\n[1] Base64\n");

    /* Known vectors (RFC 4648 test vectors). */
    struct { const char *in; const char *out; } vec[] = {
        { "",       ""         },
        { "f",      "Zg=="     },
        { "fo",     "Zm8="     },
        { "foo",    "Zm9v"     },
        { "foob",   "Zm9vYg==" },
        { "fooba",  "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
    };

    bool vectors_ok = true;
    for (const auto &v : vec) {
        std::string enc = e2e::base64_encode(
            reinterpret_cast<const unsigned char *>(v.in), std::strlen(v.in));
        if (enc != v.out) {
            vectors_ok = false;
            std::printf("      mismatch: \"%s\" -> \"%s\" (expected \"%s\")\n",
                        v.in, enc.c_str(), v.out);
        }
    }
    check("RFC 4648 known-answer vectors", vectors_ok);

    /* Round-trip every length 0..256 of random bytes: catches all three
       tail cases (0, 1, 2 leftover bytes) many times over. */
    bool roundtrip_ok = true;
    for (size_t len = 0; len <= 256 && roundtrip_ok; len++) {
        std::vector<unsigned char> data(len ? len : 1);
        if (len && !rnd(data.data(), len)) {
            check("RNG available for Base64 round-trip vectors", false);
            return;
        }

        std::string enc = e2e::base64_encode(data.data(), len);
        std::vector<unsigned char> dec;
        if (!e2e::base64_decode(enc, dec) || dec.size() != len ||
            (len && std::memcmp(dec.data(), data.data(), len) != 0))
            roundtrip_ok = false;
    }
    check("round-trip for every length 0..256 of random bytes", roundtrip_ok);

    /* The alphabet must never contain characters that would break the
       "MSG|recipient|payload" split or the outer framing. */
    std::vector<unsigned char> big(512);
    if (!rnd(big.data(), big.size())) {
        check("RNG available for the Base64 safety vector", false);
        return;
    }
    std::string enc = e2e::base64_encode(big.data(), big.size());
    bool safe = enc.find('|')  == std::string::npos &&
                enc.find(' ')  == std::string::npos &&
                enc.find('\n') == std::string::npos &&
                enc.find('\r') == std::string::npos;
    check("encoded output contains no '|', space, CR or LF", safe);

    /* Strict rejection of malformed input. */
    std::vector<unsigned char> junk;
    check("rejects bad length (not a multiple of 4)",
          !e2e::base64_decode("Zm9vY", junk));
    check("rejects illegal character '!'",
          !e2e::base64_decode("Zm9!", junk));
    check("rejects illegal character '|'",
          !e2e::base64_decode("Zm9|", junk));
    check("rejects padding inside a non-final group",
          !e2e::base64_decode("Zg==Zg==", junk));
    check("rejects '=' inside a non-final position",
          !e2e::base64_decode("Z=9vYmFy", junk));
    check("rejects over-padding '===='",
          !e2e::base64_decode("====", junk));

    /* ---- A1: canonical zero unused padding bits (RFC 4648 3.5) ----
       A non-canonical encoding decodes to the SAME bytes as the canonical
       one. Accepting it would make the transported text malleable: an
       attacker could alter the Base64 without changing the decoded blob,
       so the GCM tag would still verify. */

    /* Two '=' : only one byte is encoded, so the low 4 bits of the 2nd
       sextet are unused and must be zero.
       'Z'=25, 'g'=32 -> 32 & 0x0F == 0  -> canonical.
       'h'=33, 'i'=34, 'j'=35 all have non-zero low nibble -> must reject. */
    std::vector<unsigned char> d;
    check("canonical one-byte 'Zg==' decodes",
          e2e::base64_decode("Zg==", d) && d.size() == 1 && d[0] == 'f');
    check("rejects non-canonical 'Zh==' (unused 4 bits set)",
          !e2e::base64_decode("Zh==", d));
    check("rejects non-canonical 'Zi==' (unused 4 bits set)",
          !e2e::base64_decode("Zi==", d));
    check("rejects non-canonical 'Zj==' (unused 4 bits set)",
          !e2e::base64_decode("Zj==", d));

    /* One '=' : two bytes encoded, low 2 bits of the 3rd sextet unused.
       'Zm8=' : '8'=60, 60 & 0x03 == 0 -> canonical.
       '9'=61, '+'=62, '/'=63 -> non-zero low 2 bits -> must reject. */
    check("canonical two-byte 'Zm8=' decodes",
          e2e::base64_decode("Zm8=", d) && d.size() == 2 &&
          d[0] == 'f' && d[1] == 'o');
    check("rejects non-canonical 'Zm9=' (unused 2 bits set)",
          !e2e::base64_decode("Zm9=", d));
    check("rejects non-canonical 'Zm+=' (unused 2 bits set)",
          !e2e::base64_decode("Zm+=", d));
    check("rejects non-canonical 'Zm/=' (unused 2 bits set)",
          !e2e::base64_decode("Zm/=", d));

    /* A6: empty string is valid Base64 for zero bytes -- but is NOT a valid
       E2E payload (no room for nonce+tag). The open() side is tested in [3]. */
    check("empty string is valid Base64 decoding to zero bytes",
          e2e::base64_decode("", d) && d.empty());
}

/* ------------------------------------------------------------------ */
/* 2. AES-256-GCM round trip                                           */
/* ------------------------------------------------------------------ */

static void test_seal_open()
{
    std::printf("\n[2] AES-256-GCM seal / open\n");

    unsigned char key[e2e::KEY_BYTES];
    if (!rnd(key, sizeof(key))) {
        check("RNG available to generate the AES key", false);
        return;
    }

    const char *messages[] = {
        "",
        "a",
        "hello Bob",
        "a message with | pipes | and spaces and\ttabs",
        "unicode: \xc3\xa9\xc3\xa8\xc3\xaa \xe2\x82\xac",
    };

    bool all_ok = true;
    for (const char *m : messages) {
        std::string b64, back;
        if (!e2e::seal(key, m, b64) || !e2e::open(key, b64, back) ||
            back != std::string(m)) {
            all_ok = false;
            std::printf("      failed on: \"%s\"\n", m);
        }
    }
    check("round-trip of assorted messages (incl. empty, pipes, UTF-8)",
          all_ok);

    /* Maximum-size payload must work; one byte over must be refused. */
    std::string max_msg(e2e::MAX_E2E_PLAINTEXT, 'A');
    std::string b64, back;
    check("seals a full 2048-byte plaintext",
          e2e::seal(key, max_msg, b64) && e2e::open(key, b64, back) &&
          back == max_msg);

    std::string over(e2e::MAX_E2E_PLAINTEXT + 1, 'A');
    std::string dummy;
    check("refuses a plaintext over the 2048-byte cap",
          !e2e::seal(key, over, dummy));

    /* Size budget: the wrapped form must fit the outer 4096-byte limit. */
    std::string wrapped = "MSG|Bob|__E2E_MSG__" + b64;
    std::printf("      2048-byte plaintext -> %zu b64 chars; wrapped "
                "\"MSG|Bob|__E2E_MSG__...\" = %zu bytes (outer cap 4096)\n",
                b64.size(), wrapped.size());
    check("wrapped maximum message fits inside crypto::MAX_PLAINTEXT (4096)",
          wrapped.size() <= 4096);

    /* Fresh nonce every call: same key + same plaintext must not repeat. */
    std::string c1, c2;
    e2e::seal(key, "identical plaintext", c1);
    e2e::seal(key, "identical plaintext", c2);
    check("same key+plaintext yields different ciphertext (fresh nonce)",
          c1 != c2);
}

/* ------------------------------------------------------------------ */
/* 3. tamper rejection                                                 */
/* ------------------------------------------------------------------ */

static void test_tamper()
{
    std::printf("\n[3] Tamper and forgery rejection\n");

    unsigned char key[e2e::KEY_BYTES];
    if (!rnd(key, sizeof(key))) {
        check("RNG available to generate the AES key", false);
        return;
    }

    const std::string msg = "the quick brown fox jumps over the lazy dog";
    std::string b64;
    if (!e2e::seal(key, msg, b64)) {
        check("seal succeeded (prerequisite)", false);
        return;
    }

    std::string out;

    /* blob layout: [0..11] nonce, [12..] ciphertext, last 16 bytes tag */
    check("rejects a flipped bit in the CIPHERTEXT",
          !e2e::open(key, tamper_at(b64, e2e::NONCE_BYTES), out));

    check("rejects a flipped bit in the NONCE",
          !e2e::open(key, tamper_at(b64, 0), out));

    std::vector<unsigned char> blob;
    e2e::base64_decode(b64, blob);
    check("rejects a flipped bit in the GCM TAG",
          !e2e::open(key, tamper_at(b64, blob.size() - 1), out));

    /* Truncation. */
    std::string trunc = e2e::base64_encode(blob.data(), blob.size() - 4);
    check("rejects a truncated payload", !e2e::open(key, trunc, out));

    /* Too short to hold a nonce + tag at all. */
    unsigned char tiny[4] = {1, 2, 3, 4};
    check("rejects a payload shorter than nonce+tag",
          !e2e::open(key, e2e::base64_encode(tiny, sizeof(tiny)), out));

    /* Wrong key. */
    unsigned char other[e2e::KEY_BYTES];
    if (!rnd(other, sizeof(other))) {
        check("RNG available to generate the wrong key", false);
        return;
    }
    check("rejects decryption under the WRONG key",
          !e2e::open(other, b64, out));

    /* Malformed Base64 reaches open() and must be refused before crypto. */
    check("rejects malformed Base64 input",
          !e2e::open(key, "not!valid!base64", out));
    check("rejects empty input", !e2e::open(key, "", out));

    /* After every rejection, no plaintext may have been produced. */
    check("no plaintext leaked by any rejected input", out.empty());

    /* And the untampered original still works, proving the tests above
       failed for the right reason. */
    std::string good;
    check("the untampered original still decrypts correctly",
          e2e::open(key, b64, good) && good == msg);

    /* ---- A3: explicit failure-output contracts ---- */

    std::string sentinel = "sentinel";
    std::string over(e2e::MAX_E2E_PLAINTEXT + 1, 'A');
    bool seal_failed = !e2e::seal(key, over, sentinel);
    check("seal() returns false for an oversized plaintext", seal_failed);
    check("seal() leaves out_b64 UNTOUCHED on failure (still \"sentinel\")",
          sentinel == "sentinel");

    std::string sent2 = "sentinel";
    bool open_failed = !e2e::open(key, "not!valid!base64", sent2);
    check("open() returns false for malformed input", open_failed);
    check("open() CLEARS out_plaintext on failure", sent2.empty());

    std::string sent3 = "sentinel";
    check("open() returns false for a tampered tag",
          !e2e::open(key, tamper_at(b64, blob.size() - 1), sent3));
    check("open() CLEARS out_plaintext after tag failure", sent3.empty());

    /* ---- A6: empty string is valid Base64 but not a valid E2E payload ---- */
    std::string sent4 = "sentinel";
    check("open() rejects \"\" (valid Base64, but no nonce/tag)",
          !e2e::open(key, "", sent4));
    check("open() cleared out_plaintext for the empty-input case",
          sent4.empty());

    /* ---- A5: receive-side size guard, independent of seal()'s cap ---- */
    std::vector<unsigned char> oversized(
        e2e::NONCE_BYTES + (e2e::MAX_E2E_PLAINTEXT + 1) + e2e::TAG_BYTES);
    if (!rnd(oversized.data(), oversized.size())) {
        check("RNG available for the oversized-payload vector", false);
    } else {
        std::string over_b64 =
            e2e::base64_encode(oversized.data(), oversized.size());
        std::vector<unsigned char> rt;
        std::string out2;
        check("oversized payload is syntactically valid Base64 (prerequisite)",
              e2e::base64_decode(over_b64, rt) && rt.size() == oversized.size());
        check("open() rejects a decoded ciphertext over MAX_E2E_PLAINTEXT",
              !e2e::open(key, over_b64, out2));
    }
}

/* ------------------------------------------------------------------ */
/* 4. Checkpoint 2: offline C1<->C2 DH session establishment           */
/* ------------------------------------------------------------------ */

static void test_handshake()
{
    std::printf("\n[4] E2E handshake (offline, no sockets, no server)\n");

    e2e::E2EManager alice("alice");   /* two independent managers */
    e2e::E2EManager bob("bob");

    /* ---- Alice -> INIT ---- */
    std::string init;
    check("alice.start(\"bob\") succeeds",
          alice.start("bob", init) == e2e::Result::Ok);
    check("INIT carries the exact __E2E_INIT__ tag",
          init.rfind(e2e::TAG_INIT, 0) == 0);
    check("alice is now InitSent",
          alice.state_of("bob") == e2e::State::InitSent);

    std::vector<unsigned char> initpub;
    check("INIT payload decodes to exactly 256 DH public bytes",
          e2e::base64_decode(init.substr(std::strlen(e2e::TAG_INIT)), initpub)
          && initpub.size() == 256);

    /* ---- Bob handles INIT -> ACK ---- */
    std::string ack;
    check("bob.handle_init succeeds",
          bob.handle_init("alice", init, ack) == e2e::Result::Ok);
    check("ACK carries the exact __E2E_ACK__ tag",
          ack.rfind(e2e::TAG_ACK, 0) == 0);
    check("bob is Established after handling INIT",
          bob.state_of("alice") == e2e::State::Established);

    std::vector<unsigned char> ackpub;
    check("ACK payload decodes to 8 binding bytes + 256 DH public bytes",
          e2e::base64_decode(ack.substr(std::strlen(e2e::TAG_ACK)), ackpub)
          && ackpub.size() == e2e::BIND_BYTES + 256);

    /* ---- Alice handles ACK ---- */
    check("alice.handle_ack succeeds",
          alice.handle_ack("bob", ack) == e2e::Result::Ok);
    check("alice is Established after handling ACK",
          alice.state_of("bob") == e2e::State::Established);

    /* ---- both derived the same key, independently ---- */
    unsigned char ka[e2e::KEY_BYTES], kb[e2e::KEY_BYTES];
    bool got = alice.get_key("bob", ka) && bob.get_key("alice", kb);
    check("both sides expose an established key", got);
    check("the two independently derived 32-byte keys are IDENTICAL",
          got && CRYPTO_memcmp(ka, kb, e2e::KEY_BYTES) == 0);

    std::string fa = alice.fingerprint_of("bob");
    std::string fb = bob.fingerprint_of("alice");
    check("fingerprints are non-empty", !fa.empty() && !fb.empty());
    check("the two independently computed fingerprints MATCH", fa == fb);
    std::printf("      alice fp: %s\n      bob   fp: %s\n",
                fa.c_str(), fb.c_str());

    /* ---- the key itself is never on the wire ---- */
    std::string kb64 = e2e::base64_encode(ka, e2e::KEY_BYTES);
    check("the derived key does not appear inside INIT",
          init.find(kb64) == std::string::npos);
    check("the derived key does not appear inside ACK",
          ack.find(kb64) == std::string::npos);
    /* Also check the raw key bytes are not embedded in the decoded payloads. */
    bool leaked = false;
    for (auto *v : { &initpub, &ackpub }) {
        if (v->size() >= e2e::KEY_BYTES) {
            for (size_t i = 0; i + e2e::KEY_BYTES <= v->size(); i++)
                if (std::memcmp(v->data() + i, ka, e2e::KEY_BYTES) == 0)
                    leaked = true;
        }
    }
    check("raw key bytes do not appear in the decoded INIT/ACK payloads",
          !leaked);

    /* ---- the Checkpoint 2 key works with the Checkpoint 1 AEAD ---- */
    const std::string secret = "hello Bob -- this is end to end";
    std::string ct, back;
    check("alice seals with the DH-derived key",
          e2e::seal(ka, secret, ct));
    check("bob opens it with HIS independently derived key",
          e2e::open(kb, ct, back));
    check("bob recovers alice's exact plaintext", back == secret);

    OPENSSL_cleanse(ka, sizeof(ka));
    OPENSSL_cleanse(kb, sizeof(kb));
}

/* ------------------------------------------------------------------ */
/* 5. Checkpoint 2: rejection of malformed / out-of-state control       */
/* ------------------------------------------------------------------ */

static void test_handshake_rejects()
{
    std::printf("\n[5] Handshake rejection and session-safety rules\n");

    e2e::E2EManager m("self");
    std::string out;

    /* malformed INIT */
    check("rejects INIT with no tag",
          m.handle_init("bob", "garbage", out) == e2e::Result::BadFormat);
    check("rejects INIT with the WRONG tag",
          m.handle_init("bob", std::string(e2e::TAG_ACK) + "AAAA", out)
              == e2e::Result::BadFormat);
    check("rejects INIT with malformed Base64",
          m.handle_init("bob", std::string(e2e::TAG_INIT) + "not!b64", out)
              == e2e::Result::BadFormat);

    /* wrong decoded length */
    std::vector<unsigned char> shortpub(100, 0x42);
    check("rejects INIT whose payload is not 256 bytes",
          m.handle_init("bob",
              std::string(e2e::TAG_INIT) +
              e2e::base64_encode(shortpub.data(), shortpub.size()), out)
              == e2e::Result::BadFormat);

    /* invalid DH public value: 256 bytes of zero is out of range and must be
       rejected by the EXISTING dh validation inside compute_shared. */
    std::vector<unsigned char> zeropub(256, 0x00);
    check("rejects INIT with an invalid DH public value (all zero)",
          m.handle_init("bob",
              std::string(e2e::TAG_INIT) +
              e2e::base64_encode(zeropub.data(), zeropub.size()), out)
              == e2e::Result::DhFailure);
    check("no session was created by any rejected INIT",
          m.state_of("bob") == e2e::State::None);

    /* ACK with no pending INIT */
    e2e::E2EManager m2("self");
    /* Correctly SIZED ack (bind || pub) so it passes parsing and actually
       reaches the no-pending-handshake check. */
    std::vector<unsigned char> okpub(e2e::BIND_BYTES + 256, 0x02);
    check("rejects ACK with no pending INIT (BadState)",
          m2.handle_ack("bob",
              std::string(e2e::TAG_ACK) +
              e2e::base64_encode(okpub.data(), okpub.size()))
              == e2e::Result::BadState);
    check("rejects ACK with the wrong tag",
          m2.handle_ack("bob", std::string(e2e::TAG_INIT) + "AAAA")
              == e2e::Result::BadFormat);
    check("rejects ACK whose payload is not 256 bytes",
          m2.handle_ack("bob",
              std::string(e2e::TAG_ACK) +
              e2e::base64_encode(shortpub.data(), shortpub.size()))
              == e2e::Result::BadFormat);

    /* ---- an invalid control message must NOT destroy a live session ---- */
    e2e::E2EManager a("alice"), b("bob");
    std::string init, ack;
    a.start("bob", init);
    b.handle_init("alice", init, ack);
    a.handle_ack("bob", ack);

    unsigned char before[e2e::KEY_BYTES];
    check("prerequisite: alice established", a.get_key("bob", before));

    check("a bogus ACK is rejected once established",
          a.handle_ack("bob",
              std::string(e2e::TAG_ACK) +
              e2e::base64_encode(okpub.data(), okpub.size()))
              != e2e::Result::Ok);

    unsigned char after[e2e::KEY_BYTES];
    bool still = a.get_key("bob", after);
    check("the established session SURVIVED the bogus ACK", still);
    check("and its key is UNCHANGED",
          still && CRYPTO_memcmp(before, after, e2e::KEY_BYTES) == 0);

    check("a malformed INIT does not disturb the established key",
          b.handle_init("alice", std::string(e2e::TAG_INIT) + "!!", out)
              != e2e::Result::Ok &&
          b.state_of("alice") == e2e::State::Established);

    /* ---- a valid fresh INIT may replace the session (documented) ---- */
    e2e::E2EManager c("alice");
    std::string init2, ack2;
    check("a second handshake can be started",
          c.start("bob", init2) == e2e::Result::Ok);
    check("bob accepts a fresh INIT while already established",
          b.handle_init("alice", init2, ack2) == e2e::Result::Ok);
    check("bob is still Established after the replacement",
          b.state_of("alice") == e2e::State::Established);
    check("alice completes the replacement handshake",
          c.handle_ack("bob", ack2) == e2e::Result::Ok);

    unsigned char kc[e2e::KEY_BYTES], kb2[e2e::KEY_BYTES];
    bool both = c.get_key("bob", kc) && b.get_key("alice", kb2);
    check("the REPLACEMENT session also agrees on one key",
          both && CRYPTO_memcmp(kc, kb2, e2e::KEY_BYTES) == 0);
    check("the replacement key DIFFERS from the original",
          both && CRYPTO_memcmp(kc, before, e2e::KEY_BYTES) != 0);

    OPENSSL_cleanse(before, sizeof(before));
    OPENSSL_cleanse(after, sizeof(after));
    OPENSSL_cleanse(kc, sizeof(kc));
    OPENSSL_cleanse(kb2, sizeof(kb2));
}

/* ------------------------------------------------------------------ */
/* 6. Part A: simultaneous INIT (glare) must converge deterministically */
/* ------------------------------------------------------------------ */

static void test_glare()
{
    std::printf("\n[6] Simultaneous INIT (glare) resolution\n");

    /* Run the scenario both ways round so we cover winner-first and
       loser-first delivery orders. */
    for (int order = 0; order < 2; order++) {

        e2e::E2EManager alice("alice");
        e2e::E2EManager bob("bob");

        std::string ia, ib, ack_from_alice, ack_from_bob;

        /* Both initiate at the same moment. */
        bool started = alice.start("bob", ia) == e2e::Result::Ok &&
                       bob.start("alice", ib) == e2e::Result::Ok;
        check("both peers start a handshake simultaneously", started);
        if (!started)
            return;

        e2e::Result ra, rb;
        if (order == 0) {
            ra = alice.handle_init("bob", ib, ack_from_alice);
            rb = bob.handle_init("alice", ia, ack_from_bob);
        } else {
            rb = bob.handle_init("alice", ia, ack_from_bob);
            ra = alice.handle_init("bob", ib, ack_from_alice);
        }

        /* "alice" < "bob", so alice wins and must ignore bob's INIT. */
        check("winner (alice) IGNORES the peer INIT (GlareIgnored)",
              ra == e2e::Result::GlareIgnored);
        check("loser (bob) processes the INIT and produces an ACK",
              rb == e2e::Result::Ok);

        /* Only a side that produced an ACK actually sends one. */
        if (rb == e2e::Result::Ok)
            check("winner completes on the loser's ACK",
                  alice.handle_ack("bob", ack_from_bob) == e2e::Result::Ok);

        /* The loser's own INIT is answered by nobody. If a stray ACK were to
           arrive it must not disturb the key -- exercised in [5]. */

        check("alice ends with a usable session",
              alice.is_established("bob"));
        check("bob ends with a usable session",
              bob.is_established("alice"));

        unsigned char ka[e2e::KEY_BYTES], kb[e2e::KEY_BYTES];
        bool got = alice.get_key("bob", ka) && bob.get_key("alice", kb);
        check("both sides expose a key after glare", got);
        check("THE TWO KEYS ARE IDENTICAL (no silent divergence)",
              got && CRYPTO_memcmp(ka, kb, e2e::KEY_BYTES) == 0);
        check("fingerprints match after glare",
              alice.fingerprint_of("bob") == bob.fingerprint_of("alice"));

        check("no pending keypair is left behind on either side",
              !alice.has_pending("bob") && !bob.has_pending("alice"));

        /* And the surviving key actually works with the AEAD. */
        std::string ct, back;
        check("the converged key encrypts/decrypts correctly",
              got && e2e::seal(ka, "glare survived", ct) &&
              e2e::open(kb, ct, back) && back == "glare survived");

        OPENSSL_cleanse(ka, sizeof(ka));
        OPENSSL_cleanse(kb, sizeof(kb));

        if (order == 0)
            std::printf("      (delivery order reversed for the second run)\n");
    }
}

/* ------------------------------------------------------------------ */
/* 7. Part B: old key stays usable during a replacement handshake      */
/* ------------------------------------------------------------------ */

static void test_replacement()
{
    std::printf("\n[7] Replacement handshake keeps the old key usable\n");

    e2e::E2EManager alice("alice");
    e2e::E2EManager bob("bob");

    /* --- establish an initial session --- */
    std::string init, ack;
    bool ok = alice.start("bob", init) == e2e::Result::Ok &&
              bob.handle_init("alice", init, ack) == e2e::Result::Ok &&
              alice.handle_ack("bob", ack) == e2e::Result::Ok;
    check("initial session established", ok);
    if (!ok)
        return;

    unsigned char k_old[e2e::KEY_BYTES];
    check("initial key retrievable", alice.get_key("bob", k_old));

    std::string ct, back;
    check("initial key works",
          e2e::seal(k_old, "before replacement", ct) &&
          e2e::open(k_old, ct, back) && back == "before replacement");

    /* --- start a REPLACEMENT handshake --- */
    std::string init2, ack2;
    check("replacement handshake starts",
          alice.start("bob", init2) == e2e::Result::Ok);

    check("a handshake is now pending", alice.has_pending("bob"));
    check("state STILL reports Established (usable key exists)",
          alice.state_of("bob") == e2e::State::Established);
    check("is_established() still true while replacement pending",
          alice.is_established("bob"));

    unsigned char k_during[e2e::KEY_BYTES];
    check("the OLD key is still obtainable mid-replacement",
          alice.get_key("bob", k_during));
    check("and it is unchanged",
          CRYPTO_memcmp(k_old, k_during, e2e::KEY_BYTES) == 0);

    std::string ct2, back2;
    check("the OLD key still encrypts/decrypts mid-replacement",
          e2e::seal(k_during, "during replacement", ct2) &&
          e2e::open(k_old, ct2, back2) && back2 == "during replacement");

    /* --- complete the replacement --- */
    check("peer answers the replacement INIT",
          bob.handle_init("alice", init2, ack2) == e2e::Result::Ok);
    check("initiator completes the replacement",
          alice.handle_ack("bob", ack2) == e2e::Result::Ok);

    unsigned char k_new[e2e::KEY_BYTES], k_bob[e2e::KEY_BYTES];
    bool both = alice.get_key("bob", k_new) && bob.get_key("alice", k_bob);
    check("both peers agree on the NEW key",
          both && CRYPTO_memcmp(k_new, k_bob, e2e::KEY_BYTES) == 0);
    check("the new key DIFFERS from the old key",
          both && CRYPTO_memcmp(k_new, k_old, e2e::KEY_BYTES) != 0);
    check("no pending handshake remains", !alice.has_pending("bob"));

    /* --- a FAILED replacement must leave the working key intact --- */
    std::string init3;
    check("another replacement starts",
          alice.start("bob", init3) == e2e::Result::Ok);

    /* A forged ACK (correct size, wrong binding) is now rejected at the
       BINDING check, before any DH work. */
    std::vector<unsigned char> junkpub(e2e::BIND_BYTES + 256, 0x00);
    check("a forged ACK is rejected by the binding check",
          alice.handle_ack("bob",
              std::string(e2e::TAG_ACK) +
              e2e::base64_encode(junkpub.data(), junkpub.size()))
              != e2e::Result::Ok);

    unsigned char k_after[e2e::KEY_BYTES];
    check("session still usable after the FAILED replacement",
          alice.get_key("bob", k_after));
    check("and the key is UNCHANGED by the failure",
          CRYPTO_memcmp(k_new, k_after, e2e::KEY_BYTES) == 0);
    /* Improved contract: a mismatched ACK no longer consumes the live
       handshake, so the genuine ACK can still complete it. */
    check("the live pending handshake SURVIVES a forged ACK",
          alice.has_pending("bob"));

    OPENSSL_cleanse(k_old, sizeof(k_old));
    OPENSSL_cleanse(k_new, sizeof(k_new));
    OPENSSL_cleanse(k_bob, sizeof(k_bob));
    OPENSSL_cleanse(k_after, sizeof(k_after));
    OPENSSL_cleanse(k_during, sizeof(k_during));
}

/* ------------------------------------------------------------------ */
/* 8. Part A/B: stale (delayed) ACK from a superseded handshake        */
/* ------------------------------------------------------------------ */

static void test_stale_ack()
{
    std::printf("\n[8] Delayed/stale ACK binding\n");

    e2e::E2EManager alice("alice");
    e2e::E2EManager bob("bob");

    /* --- H1: Alice INIT(A1); Bob answers with ACK(B1) which we DELAY --- */
    std::string i1, ack1;
    bool h1 = alice.start("bob", i1) == e2e::Result::Ok &&
              bob.handle_init("alice", i1, ack1) == e2e::Result::Ok;
    check("H1: bob produced a valid ACK (held back, not delivered)", h1);
    if (!h1)
        return;

    unsigned char k_bob_h1[e2e::KEY_BYTES];
    check("bob established a key from H1", bob.get_key("alice", k_bob_h1));

    /* --- H2: Alice starts a replacement, superseding pending A1 --- */
    std::string i2, ack2;
    check("H2: alice starts a replacement handshake",
          alice.start("bob", i2) == e2e::Result::Ok);
    check("alice has a pending handshake (A2)", alice.has_pending("bob"));
    check("alice has NO usable key yet", !alice.is_established("bob"));

    /* --- now deliver the delayed, cryptographically valid ACK(B1) --- */
    e2e::Result stale = alice.handle_ack("bob", ack1);

    check("the STALE ACK is REJECTED", stale != e2e::Result::Ok);
    check("stale ACK did not install any key",
          !alice.is_established("bob"));
    check("stale ACK did NOT consume the live pending handshake",
          alice.has_pending("bob"));

    /* --- the genuine H2 ACK must still complete --- */
    check("bob answers the H2 INIT",
          bob.handle_init("alice", i2, ack2) == e2e::Result::Ok);
    check("alice completes H2 with its own ACK",
          alice.handle_ack("bob", ack2) == e2e::Result::Ok);

    unsigned char ka[e2e::KEY_BYTES], kb[e2e::KEY_BYTES];
    bool both = alice.get_key("bob", ka) && bob.get_key("alice", kb);
    check("both peers now hold a key", both);
    check("H2 KEYS MATCH (no divergence)",
          both && CRYPTO_memcmp(ka, kb, e2e::KEY_BYTES) == 0);
    check("the H2 key differs from bob's superseded H1 key",
          both && CRYPTO_memcmp(ka, k_bob_h1, e2e::KEY_BYTES) != 0);
    check("fingerprints match after the stale-ACK episode",
          alice.fingerprint_of("bob") == bob.fingerprint_of("alice"));

    std::string ct, back;
    check("the converged key works end to end",
          both && e2e::seal(ka, "after stale ack", ct) &&
          e2e::open(kb, ct, back) && back == "after stale ack");

    OPENSSL_cleanse(ka, sizeof(ka));
    OPENSSL_cleanse(kb, sizeof(kb));
    OPENSSL_cleanse(k_bob_h1, sizeof(k_bob_h1));
}

/* ------------------------------------------------------------------ */
/* 9. Part C/D: no stale control message may disturb a LIVE key        */
/* ------------------------------------------------------------------ */

static void test_stale_cannot_disturb_established()
{
    std::printf("\n[9] Stale control messages vs an established key\n");

    e2e::E2EManager alice("alice");
    e2e::E2EManager bob("bob");

    /* Establish a working session. */
    std::string i1, a1;
    bool ok = alice.start("bob", i1) == e2e::Result::Ok &&
              bob.handle_init("alice", i1, a1) == e2e::Result::Ok &&
              alice.handle_ack("bob", a1) == e2e::Result::Ok;
    check("baseline session established", ok);
    if (!ok)
        return;

    unsigned char k0[e2e::KEY_BYTES];
    check("baseline key retrievable", alice.get_key("bob", k0));

    /* Replay the SAME ACK now that nothing is pending. */
    e2e::Result r = alice.handle_ack("bob", a1);
    unsigned char k1[e2e::KEY_BYTES];
    check("replayed ACK is rejected once established",
          r != e2e::Result::Ok);
    check("key still present after the replay", alice.get_key("bob", k1));
    check("KEY BYTES UNCHANGED after the replay",
          CRYPTO_memcmp(k0, k1, e2e::KEY_BYTES) == 0);
    check("state still Established", 
          alice.state_of("bob") == e2e::State::Established);

    /* Start a replacement, then feed the OLD ack while H2 is pending. */
    std::string i2, a2;
    check("replacement handshake started",
          alice.start("bob", i2) == e2e::Result::Ok);

    unsigned char kmid[e2e::KEY_BYTES];
    check("old key STILL usable while replacement pending",
          alice.get_key("bob", kmid));
    check("and unchanged mid-replacement",
          CRYPTO_memcmp(k0, kmid, e2e::KEY_BYTES) == 0);

    check("stale ACK rejected while a replacement is pending",
          alice.handle_ack("bob", a1) != e2e::Result::Ok);

    unsigned char kafter[e2e::KEY_BYTES];
    check("old key survived the stale ACK", alice.get_key("bob", kafter));
    check("KEY BYTES UNCHANGED by the stale ACK",
          CRYPTO_memcmp(k0, kafter, e2e::KEY_BYTES) == 0);
    check("the live pending handshake was NOT consumed",
          alice.has_pending("bob"));

    /* And the real replacement still completes. */
    check("peer answers the replacement",
          bob.handle_init("alice", i2, a2) == e2e::Result::Ok);
    check("replacement completes",
          alice.handle_ack("bob", a2) == e2e::Result::Ok);

    unsigned char knew[e2e::KEY_BYTES], kbob[e2e::KEY_BYTES];
    bool both = alice.get_key("bob", knew) && bob.get_key("alice", kbob);
    check("both agree on the replacement key",
          both && CRYPTO_memcmp(knew, kbob, e2e::KEY_BYTES) == 0);
    check("replacement key differs from the baseline",
          both && CRYPTO_memcmp(knew, k0, e2e::KEY_BYTES) != 0);

    /* Malformed ACK must also leave the key alone. */
    check("malformed ACK rejected",
          alice.handle_ack("bob", std::string(e2e::TAG_ACK) + "!!!")
              != e2e::Result::Ok);
    unsigned char kfin[e2e::KEY_BYTES];
    check("key still present after malformed ACK",
          alice.get_key("bob", kfin));
    check("KEY BYTES UNCHANGED by the malformed ACK",
          CRYPTO_memcmp(knew, kfin, e2e::KEY_BYTES) == 0);

    OPENSSL_cleanse(k0, sizeof(k0));   OPENSSL_cleanse(k1, sizeof(k1));
    OPENSSL_cleanse(kmid, sizeof(kmid)); OPENSSL_cleanse(kafter, sizeof(kafter));
    OPENSSL_cleanse(knew, sizeof(knew)); OPENSSL_cleanse(kbob, sizeof(kbob));
    OPENSSL_cleanse(kfin, sizeof(kfin));
}

/* ------------------------------------------------------------------ */

int main()
{
    std::printf("e2e_test -- Phase 4 Checkpoints 1-2 "
                "(Base64, AES-256-GCM, E2E DH handshake, glare, replacement)\n");

    test_base64();
    test_seal_open();
    test_tamper();
    test_handshake();
    test_handshake_rejects();
    test_glare();
    test_replacement();
    test_stale_ack();
    test_stale_cannot_disturb_established();

    std::printf("\nResult: %s\n", g_pass ? "all checks passed"
                                         : "CHECKS FAILED");
    return g_pass ? 0 : 1;
}
