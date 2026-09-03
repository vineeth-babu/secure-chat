/*
 * certs.h -- server authentication via PKI (Phase 3)
 *
 * Runs BEFORE the Diffie-Hellman exchange:
 *   1. server sends its X.509 certificate (DER)
 *   2. client validates it against a locally trusted CA root (signature
 *      chain, validity period, expected IP identity)
 *   3. server proves it holds the matching private key by signing a fresh
 *      32-byte random challenge from the client
 * Any failure aborts the connection before a single DH byte goes out.
 *
 * Only low-level X.509/EVP primitives are used here -- x509.h, evp.h, pem.h,
 * rand.h. No TLS/SSL, no DH/ECDH exchange API. EVP_DigestSign/Verify are
 * plain digital-signature primitives, not key agreement.
 *
 * Wire framing is the same [4-byte big-endian length] + payload convention
 * used elsewhere, via net::write_all / net::read_exact.
 */

#ifndef CERTS_H
#define CERTS_H

#include <openssl/x509.h>
#include <openssl/evp.h>

#include <cstddef>
#include <string>

namespace certs {

/* Fresh random challenge size, in bytes. */
constexpr size_t CHALLENGE_BYTES = 32;

/* Defensive caps on network-controlled lengths, checked before allocation. */
constexpr size_t MAX_CERT_BYTES = 8192;   /* an RSA-2048 leaf is ~1-1.5 KB */
constexpr size_t MAX_SIG_BYTES  = 1024;   /* RSA-2048 sig = 256 B          */

/* -------------------- server-side loading (startup) -------------------- */

/* Load the server's certificate (PEM) and matching private key (PEM).
   Returns nullptr on failure with a reason in *why. Caller frees with
   X509_free / EVP_PKEY_free. */
X509     *load_cert_file(const char *path, std::string *why);
EVP_PKEY *load_privkey_file(const char *path, std::string *why);

/* Confirm the private key matches the certificate's public key -- catches a
   mismatched cert/key pair at startup instead of failing weirdly later. */
bool key_matches_cert(X509 *cert, EVP_PKEY *key, std::string *why);

/* -------------------- client-side loading (startup) -------------------- */

/* Build an X509_STORE containing the trusted CA root (PEM). The client
   validates received certificates against this. Caller frees with
   X509_STORE_free. */
X509_STORE *load_ca_store(const char *ca_path, std::string *why);

/* -------------------- the authentication exchange ---------------------- */

/*
 * Server side, runs before dh::run_handshake: send our cert (DER,
 * length-framed), read the client's 32-byte challenge, sign it
 * (EVP_DigestSign, SHA-256) and send the signature back.
 * Returns false with a reason in *why on any failure; caller drops the
 * connection instead of moving on to DH.
 */
bool server_send_auth(int fd, X509 *cert, EVP_PKEY *key, std::string *why);

/*
 * Client side, runs before dh::run_handshake: receive the server cert and
 * validate it against ca_store (signature chain, validity, and expected_ip
 * as an IP SAN), send a fresh 32-byte challenge, then verify the returned
 * signature with the cert's public key.
 * On any failure returns false and guarantees nothing further was sent (no
 * DH, no username).
 */
bool client_verify_auth(int fd, X509_STORE *ca_store,
                        const char *expected_ip, std::string *why);

}  /* namespace certs */

#endif /* CERTS_H */
