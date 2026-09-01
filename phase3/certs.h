/*
 * certs.h -- CS6008 Phase 3: server authentication via PKI
 *
 * Adds, BEFORE the untouched Phase 2 DH exchange:
 *   1. the server sends its X.509 certificate (DER);
 *   2. the client validates it against a locally trusted CA root
 *      (signature chain, validity period, expected IP identity);
 *   3. the server proves possession of the matching private key by signing
 *      a fresh 32-byte random challenge the client generates.
 * Any failure aborts the connection before a single DH byte is sent.
 *
 * Allowed-tools note (assignment §1.2): this module uses only the low-level
 * X.509 / EVP primitives that the assignment explicitly permits as building
 * blocks -- <openssl/x509.h>, <openssl/evp.h>, <openssl/pem.h>,
 * <openssl/rand.h>. It uses NO TLS/SSL (<openssl/ssl.h>) and NO DH/ECDH
 * exchange API. EVP_DigestSign / EVP_DigestVerify are digital-signature
 * primitives, not key agreement.
 *
 * Wire framing reuses the Phase 2 convention: [4-byte big-endian length]
 * followed by that many bytes, carried by net::write_all / net::read_exact.
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

/* Confirm the private key matches the certificate's public key. A mismatch
   at startup is a deployment error worth catching before accepting clients. */
bool key_matches_cert(X509 *cert, EVP_PKEY *key, std::string *why);

/* -------------------- client-side loading (startup) -------------------- */

/* Build an X509_STORE containing the trusted CA root (PEM). The client
   validates received certificates against this. Caller frees with
   X509_STORE_free. */
X509_STORE *load_ca_store(const char *ca_path, std::string *why);

/* -------------------- the authentication exchange ---------------------- */

/*
 * Server side. Runs on the connection socket BEFORE dh::run_handshake:
 *   - send our certificate (DER, length-framed);
 *   - read the client's 32-byte challenge;
 *   - sign it with our private key (EVP_DigestSign, SHA-256);
 *   - send the signature (length-framed).
 * Returns false (reason in *why) on any socket or crypto failure; the caller
 * then drops the connection without proceeding to DH.
 */
bool server_send_auth(int fd, X509 *cert, EVP_PKEY *key, std::string *why);

/*
 * Client side. Runs on the connection socket BEFORE dh::run_handshake:
 *   - receive the server certificate and validate it against ca_store
 *     (signature chain + validity period), then check the expected identity
 *     (expected_ip must appear as an IP SAN);
 *   - generate a fresh 32-byte challenge and send it;
 *   - receive the signature and verify it with the certificate's public key.
 * On ANY failure returns false with a reason in *why and guarantees nothing
 * further (no DH, no username) has been sent.
 */
bool client_verify_auth(int fd, X509_STORE *ca_store,
                        const char *expected_ip, std::string *why);

}  /* namespace certs */

#endif /* CERTS_H */
