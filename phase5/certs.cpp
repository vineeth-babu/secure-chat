/*
 * certs.cpp -- server authentication via PKI (Phase 3)
 *
 * See certs.h for what this is for. No SSL, no DH/ECDH exchange API here.
 */

#include "certs.h"
#include "net.h"

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace certs {

// length-framed send/recv, same convention as the rest of the project

static bool send_framed(int fd, const unsigned char *buf, size_t len)
{
    uint32_t netlen = htonl(static_cast<uint32_t>(len));
    if (!net::write_all(fd, &netlen, sizeof(netlen)))
        return false;
    return net::write_all(fd, buf, len);
}

/* Reads a [4-byte BE length][payload] frame, rejecting any length above cap
   BEFORE allocating. On success fills out and returns true. */
static bool recv_framed(int fd, std::vector<unsigned char> &out, size_t cap)
{
    uint32_t netlen = 0;
    if (!net::read_exact(fd, &netlen, sizeof(netlen)))
        return false;

    uint32_t len = ntohl(netlen);
    if (len == 0 || len > cap)
        return false;

    out.resize(len);
    return net::read_exact(fd, out.data(), len);
}

// loading certs/keys from disk

X509 *load_cert_file(const char *path, std::string *why)
{
    FILE *fp = std::fopen(path, "r");
    if (fp == nullptr) {
        if (why) *why = std::string("cannot open certificate file: ") + path;
        return nullptr;
    }

    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);

    if (cert == nullptr && why)
        *why = std::string("failed to parse PEM certificate: ") + path;
    return cert;
}

EVP_PKEY *load_privkey_file(const char *path, std::string *why)
{
    FILE *fp = std::fopen(path, "r");
    if (fp == nullptr) {
        if (why) *why = std::string("cannot open private key file: ") + path;
        return nullptr;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);

    if (key == nullptr && why)
        *why = std::string("failed to parse PEM private key: ") + path;
    return key;
}

bool key_matches_cert(X509 *cert, EVP_PKEY *key, std::string *why)
{
    /* X509_check_private_key returns 1 when the key matches the cert's
       public key. Catches a cert/key mismatch at startup. */
    if (X509_check_private_key(cert, key) != 1) {
        if (why) *why = "server private key does not match the certificate";
        return false;
    }
    return true;
}

X509_STORE *load_ca_store(const char *ca_path, std::string *why)
{
    X509_STORE *store = X509_STORE_new();
    if (store == nullptr) {
        if (why) *why = "X509_STORE_new failed";
        return nullptr;
    }

    X509 *ca = load_cert_file(ca_path, why);
    if (ca == nullptr) {
        X509_STORE_free(store);
        return nullptr;
    }

    if (X509_STORE_add_cert(store, ca) != 1) {
        if (why) *why = "failed to add CA certificate to the trust store";
        X509_free(ca);
        X509_STORE_free(store);
        return nullptr;
    }

    X509_free(ca);      /* the store took its own reference */
    return store;
}

// certificate validation

/*
 * Checks the signature chains to the trusted CA and that we're within the
 * validity period (X509_verify_cert enforces notBefore/notAfter), then
 * separately checks the expected server IP is present as an IP SAN.
 */
static bool validate_cert(X509 *cert, X509_STORE *store,
                          const char *expected_ip, std::string *why)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == nullptr) {
        if (why) *why = "X509_STORE_CTX_new failed";
        return false;
    }

    bool ok = false;

    if (X509_STORE_CTX_init(ctx, store, cert, nullptr) != 1) {
        if (why) *why = "X509_STORE_CTX_init failed";
        goto done;
    }

    /* covers both the CA chain and the validity period; the error code
       tells us which one failed */
    if (X509_verify_cert(ctx) != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        if (why) {
            *why = std::string("certificate validation failed: ") +
                   X509_verify_cert_error_string(err);
        }
        goto done;
    }

    /* the server is reached by IP, so the IP has to show up as an IP SAN.
       X509_check_ip_asc returns 1 on a match -- this is what stops a
       validly-signed cert for the wrong host. */
    if (X509_check_ip_asc(cert, expected_ip, 0) != 1) {
        if (why) {
            *why = std::string("certificate identity mismatch: ") +
                   expected_ip + " is not present as an IP SAN";
        }
        goto done;
    }

    ok = true;

done:
    X509_STORE_CTX_free(ctx);
    return ok;
}

// signing / verifying the challenge

// signs msg with key using EVP_DigestSign (SHA-256), fills sig_out
static bool sign_message(EVP_PKEY *key,
                         const unsigned char *msg, size_t msglen,
                         std::vector<unsigned char> &sig_out,
                         std::string *why)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == nullptr) {
        if (why) *why = "EVP_MD_CTX_new failed";
        return false;
    }

    bool ok = false;
    size_t siglen = 0;

    if (EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, key) != 1) {
        if (why) *why = "EVP_DigestSignInit failed";
        goto done;
    }

    // first call just asks for the length
    if (EVP_DigestSign(md, nullptr, &siglen, msg, msglen) != 1) {
        if (why) *why = "EVP_DigestSign (size query) failed";
        goto done;
    }

    if (siglen == 0 || siglen > MAX_SIG_BYTES) {
        if (why) *why = "unexpected signature length";
        goto done;
    }

    sig_out.resize(siglen);
    if (EVP_DigestSign(md, sig_out.data(), &siglen, msg, msglen) != 1) {
        if (why) *why = "EVP_DigestSign failed";
        goto done;
    }
    sig_out.resize(siglen);
    ok = true;

done:
    EVP_MD_CTX_free(md);
    return ok;
}

// verifies sig over msg with the public key pulled from cert
static bool verify_message(X509 *cert,
                           const unsigned char *msg, size_t msglen,
                           const unsigned char *sig, size_t siglen,
                           std::string *why)
{
    EVP_PKEY *pub = X509_get_pubkey(cert);
    if (pub == nullptr) {
        if (why) *why = "cannot extract public key from certificate";
        return false;
    }

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == nullptr) {
        EVP_PKEY_free(pub);
        if (why) *why = "EVP_MD_CTX_new failed";
        return false;
    }

    bool ok = false;

    if (EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, pub) != 1) {
        if (why) *why = "EVP_DigestVerifyInit failed";
        goto done;
    }

    // only a return of 1 means the signature is good
    if (EVP_DigestVerify(md, sig, siglen, msg, msglen) != 1) {
        if (why) *why = "proof-of-possession failed: signature did not verify";
        goto done;
    }

    ok = true;

done:
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pub);
    return ok;
}

// server side

bool server_send_auth(int fd, X509 *cert, EVP_PKEY *key, std::string *why)
{
    // send our certificate as DER, length-framed
    unsigned char *der = nullptr;
    int derlen = i2d_X509(cert, &der);
    if (derlen <= 0 || der == nullptr) {
        if (why) *why = "i2d_X509 failed to serialise certificate";
        return false;
    }

    bool sent = send_framed(fd, der, static_cast<size_t>(derlen));
    OPENSSL_free(der);
    if (!sent) {
        if (why) *why = "failed to send certificate";
        return false;
    }

    // read the client's fresh challenge
    std::vector<unsigned char> challenge;
    if (!recv_framed(fd, challenge, CHALLENGE_BYTES + 16)) {
        if (why) *why = "failed to read client challenge";
        return false;
    }
    if (challenge.size() != CHALLENGE_BYTES) {
        if (why) *why = "client challenge has unexpected size";
        return false;
    }

    // sign the challenge and send the signature back
    std::vector<unsigned char> sig;
    if (!sign_message(key, challenge.data(), challenge.size(), sig, why))
        return false;

    if (!send_framed(fd, sig.data(), sig.size())) {
        if (why) *why = "failed to send signature";
        return false;
    }

    return true;
}

// client side

bool client_verify_auth(int fd, X509_STORE *ca_store,
                        const char *expected_ip, std::string *why)
{
    // receive the server certificate (DER, length-framed, bounded)
    std::vector<unsigned char> der;
    if (!recv_framed(fd, der, MAX_CERT_BYTES)) {
        if (why) *why = "failed to read server certificate";
        return false;
    }

    const unsigned char *p = der.data();
    X509 *cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (cert == nullptr) {
        if (why) *why = "server sent malformed certificate (d2i_X509 failed)";
        return false;
    }

    // validate: CA chain, validity period, expected IP SAN. Any failure
    // stops us here, before we send a challenge or touch DH.
    if (!validate_cert(cert, ca_store, expected_ip, why)) {
        X509_free(cert);
        return false;
    }

    // fresh random challenge from the CSPRNG
    unsigned char challenge[CHALLENGE_BYTES];
    if (RAND_bytes(challenge, sizeof(challenge)) != 1) {
        if (why) *why = "RAND_bytes failed to generate challenge";
        X509_free(cert);
        return false;
    }

    if (!send_framed(fd, challenge, sizeof(challenge))) {
        if (why) *why = "failed to send challenge";
        X509_free(cert);
        return false;
    }

    // receive and verify the signature over our challenge
    std::vector<unsigned char> sig;
    if (!recv_framed(fd, sig, MAX_SIG_BYTES)) {
        if (why) *why = "failed to read signature";
        X509_free(cert);
        return false;
    }

    bool ok = verify_message(cert, challenge, sizeof(challenge),
                             sig.data(), sig.size(), why);

    OPENSSL_cleanse(challenge, sizeof(challenge));
    X509_free(cert);
    return ok;
}

}  /* namespace certs */
