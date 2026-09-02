/*
 * mitm_proxy_p3.cpp -- CS6008 Phase 3 §4.2: the Phase 2 MITM, re-run and defeated
 *
 * This is a genuine update of the Phase 2 two-socket MITM
 * (mitm_proxy.cpp), NOT a local fake server. It keeps the same architecture:
 *
 *     Victim client  <-->  Mallory (this process)  <-->  Real server
 *
 * Mallory listens for the victim AND opens a real TCP connection to the
 * genuine Phase 3 server, exactly as in Phase 2. The only thing added is the
 * Phase 3 authentication step the victim now performs first -- and that step
 * is what defeats the attack, in one of two clearly distinct ways:
 *
 *   mode "fake"    Mallory presents a self-signed certificate it made itself.
 *                 The victim's CA check rejects it (does not chain to the
 *                 trusted CA). The victim aborts BEFORE sending its challenge,
 *                 so Mallory never reaches DH and never sees plaintext.
 *
 *   mode "copied" Mallory presents a byte-for-byte copy of the REAL server
 *                 certificate (public, trivially copyable) but does NOT have
 *                 the server's private key. The victim's CA + identity checks
 *                 PASS, so the victim sends a fresh challenge. Mallory cannot
 *                 sign that challenge (no private key), so it sends a bogus
 *                 signature; the victim's proof-of-possession check fails and
 *                 it aborts before DH.
 *
 * In BOTH modes the victim never begins DH with Mallory, so the Phase 2
 * plaintext-relay stage is never reached -- the exact opposite of Phase 2.
 *
 * HONEST LIMITATION (documented for the report). The server signs only the
 * client's challenge; the signature is not bound to the DH public values.
 * Therefore a copied-cert Mallory that *forwards the victim's challenge to the
 * real server* and relays the real signature back WOULD pass proof-of-
 * possession, and could then run the Phase 2 two-DH attack. This driver
 * deliberately demonstrates the non-forwarding attempt (Mallory acting as the
 * server itself), which fails, and prints a note pointing at challenge->DH
 * binding as the fix. That binding is the natural Phase 3 hardening / Phase 4
 * groundwork. We do NOT weaken validation or PoP to make the attack "work".
 *
 * Reuses the project's own dh.*, crypto.*, net.*, certs.* -- no TLS/SSL, no
 * DH/ECDH exchange API.
 *
 * Build:  make mitm_proxy_p3
 * Usage:
 *   ./mitm_proxy_p3 <listen_port> <server_ip> <server_port> \
 *                   <fake|copied> <cert.pem> [key.pem]
 *
 *   fake:    cert.pem = a self-signed cert Mallory generated (rogue-cert.pem).
 *            key.pem may be given but is irrelevant; validation fails first.
 *   copied:  cert.pem = a copy of the real server-cert.pem. No key.pem, since
 *            the whole point is that Mallory lacks the matching private key.
 *
 * Run Mallory on the Mallory VM; point the victim at Mallory:
 *   ./client <mallory-ip> <listen_port> ca-cert.pem
 */

#include "dh.h"
#include "crypto.h"
#include "net.h"
#include "certs.h"

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

/* ------------------------------------------------------------------ */
/* length-framed helpers (same wire convention as certs.cpp)           */
/* ------------------------------------------------------------------ */

static bool send_framed(int fd, const unsigned char *buf, size_t len)
{
    uint32_t netlen = htonl(static_cast<uint32_t>(len));
    if (!net::write_all(fd, &netlen, sizeof(netlen)))
        return false;
    return net::write_all(fd, buf, len);
}

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

/* ------------------------------------------------------------------ */
/* connect to the real server (identical to Phase 2 MITM)              */
/* ------------------------------------------------------------------ */

static int connect_to_server(const char *server_ip, int server_port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::perror("[mitm-p3] socket");
        return -1;
    }

    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(static_cast<uint16_t>(server_port));
    if (inet_pton(AF_INET, server_ip, &saddr.sin_addr) <= 0) {
        std::fprintf(stderr, "[mitm-p3] bad server ip\n");
        close(server_fd);
        return -1;
    }
    if (connect(server_fd, reinterpret_cast<sockaddr *>(&saddr),
                sizeof(saddr)) < 0) {
        std::perror("[mitm-p3] connect to real server");
        close(server_fd);
        return -1;
    }
    return server_fd;
}

/* ------------------------------------------------------------------ */
/* one intercepted session                                             */
/* ------------------------------------------------------------------ */

static void handle_victim(int victim_fd, const char *server_ip,
                          int server_port, const std::string &mode,
                          X509 *cert, EVP_PKEY *key)
{
    /* ---- genuine two-socket MITM: open a real link to the server ---- */
    int server_fd = connect_to_server(server_ip, server_port);
    if (server_fd < 0) {
        std::printf("[mitm-p3] could not reach the real server; aborting "
                    "this session.\n");
        std::fflush(stdout);
        close(victim_fd);
        return;
    }

    std::printf("\n[mitm-p3] victim connected; opened a real session to the "
                "server %s:%d (Phase 2-style two-socket MITM).\n",
                server_ip, server_port);

    /*
     * The real server speaks first in Phase 3: it sends its certificate, then
     * reads a challenge, then signs it. To stay a faithful Phase 2-style MITM
     * we must consume the server's certificate frame from the server link so
     * the two sockets don't desynchronise. We read it and discard it: Mallory
     * cannot use the real cert as its own without the matching key anyway.
     */
    std::vector<unsigned char> real_cert_der;
    if (!recv_framed(server_fd, real_cert_der, certs::MAX_CERT_BYTES)) {
        std::printf("[mitm-p3] server did not send a certificate; aborting.\n");
        std::fflush(stdout);
        close(victim_fd);
        close(server_fd);
        return;
    }
    std::printf("[mitm-p3] consumed the real server's certificate on the "
                "server link (%zu bytes).\n", real_cert_der.size());
    std::fflush(stdout);

    /* ---- present OUR certificate to the victim (fake or copied) ---- */
    unsigned char *der = nullptr;
    int derlen = i2d_X509(cert, &der);
    if (derlen <= 0 || !send_framed(victim_fd, der, static_cast<size_t>(derlen))) {
        OPENSSL_free(der);
        std::printf("[mitm-p3] failed to send our certificate to the victim.\n");
        close(victim_fd);
        close(server_fd);
        return;
    }
    OPENSSL_free(der);
    std::printf("[mitm-p3] presented our '%s' certificate to the victim.\n",
                mode.c_str());
    std::fflush(stdout);

    /* ---- try to read the victim's challenge ---- */
    std::vector<unsigned char> challenge;
    if (!recv_framed(victim_fd, challenge, certs::CHALLENGE_BYTES + 16)) {
        /* fake mode lands here: the victim rejected the cert at validation
           and closed without ever sending a challenge. */
        std::printf("\n[mitm-p3] === DEFEATED at CERTIFICATE VALIDATION ===\n");
        std::printf("[mitm-p3] The victim rejected our certificate (it does "
                    "not chain to the trusted CA) and sent NO challenge.\n");
        std::printf("[mitm-p3] No DH, no plaintext. Contrast with Phase 2, "
                    "where the same proxy reached plaintext relay.\n");
        std::fflush(stdout);
        close(victim_fd);
        close(server_fd);
        return;
    }

    /* copied mode reaches here: the victim accepted the (genuine) certificate
       and sent a fresh challenge. */
    std::printf("[mitm-p3] the victim ACCEPTED the certificate and sent a "
                "%zu-byte challenge.\n", challenge.size());
    std::printf("[mitm-p3] attempting to prove possession of the private "
                "key we do NOT have...\n");
    std::fflush(stdout);

    /* Try to sign. In copied mode we hold no key (key == nullptr), so we
       cannot produce a valid signature; send a bogus one so the victim's
       verify step visibly runs and fails rather than hanging. If a (wrong)
       key was supplied, sign with it -- the victim's check against the
       certificate's real public key will still fail. */
    std::vector<unsigned char> sig;
    bool signed_ok = false;

    if (key != nullptr) {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        size_t siglen = 0;
        if (md &&
            EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, key) == 1 &&
            EVP_DigestSign(md, nullptr, &siglen,
                           challenge.data(), challenge.size()) == 1) {
            sig.resize(siglen);
            if (EVP_DigestSign(md, sig.data(), &siglen,
                               challenge.data(), challenge.size()) == 1) {
                sig.resize(siglen);
                signed_ok = true;
            }
        }
        EVP_MD_CTX_free(md);
        if (signed_ok)
            std::printf("[mitm-p3] signed with a NON-matching key; the "
                        "victim's check against the cert's real public key "
                        "will fail.\n");
    }

    if (!signed_ok) {
        sig.assign(256, 0x00);
        RAND_bytes(sig.data(), static_cast<int>(sig.size()));
        std::printf("[mitm-p3] no matching private key -- sending a bogus "
                    "signature.\n");
    }
    std::fflush(stdout);

    send_framed(victim_fd, sig.data(), sig.size());

    std::printf("\n[mitm-p3] === DEFEATED at PROOF-OF-POSSESSION ===\n");
    std::printf("[mitm-p3] Our signature cannot satisfy the victim's public-"
                "key check, because we lack the server's private key.\n");
    std::printf("[mitm-p3] The victim aborts before DH. No plaintext.\n");
    std::printf("[mitm-p3] NOTE: the signature covers only the challenge, not "
                "the DH keys. A Mallory that FORWARDED the victim's challenge "
                "to the real server and relayed the real signature back would "
                "pass this check -- binding challenge||client_pub||server_pub "
                "is the fix, and the Phase 4 groundwork.\n");
    std::fflush(stdout);

    close(victim_fd);
    close(server_fd);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 6) {
        std::fprintf(stderr,
            "usage: %s <listen_port> <server_ip> <server_port> "
            "<fake|copied> <cert.pem> [key.pem]\n"
            "  fake:   present a self-signed cert; defeated at validation\n"
            "  copied: present a copy of the real cert with NO key;\n"
            "          defeated at proof-of-possession\n", argv[0]);
        return 1;
    }

    const int   listen_port = std::atoi(argv[1]);
    const char *server_ip   = argv[2];
    const int   server_port = std::atoi(argv[3]);
    const std::string mode  = argv[4];
    const char *cert_path   = argv[5];
    const char *key_path    = (argc > 6) ? argv[6] : nullptr;

    if (mode != "fake" && mode != "copied") {
        std::fprintf(stderr, "mode must be 'fake' or 'copied'\n");
        return 1;
    }

    std::string why;

    X509 *cert = certs::load_cert_file(cert_path, &why);
    if (cert == nullptr) {
        std::fprintf(stderr, "[mitm-p3] cannot load cert %s: %s\n",
                     cert_path, why.c_str());
        return 1;
    }

    /* Mallory only has a private key in the 'fake' case (its own self-signed
       pair). In 'copied' mode it deliberately has none -- that is the point. */
    EVP_PKEY *key = nullptr;
    if (key_path != nullptr) {
        key = certs::load_privkey_file(key_path, &why);
        if (key == nullptr)
            std::fprintf(stderr, "[mitm-p3] (note) no usable key: %s\n",
                         why.c_str());
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(listen_port));

    if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        return 1;
    }
    listen(listen_fd, 4);

    std::printf("[mitm-p3] mode=%s, listening on port %d, real server %s:%d\n",
                mode.c_str(), listen_port, server_ip, server_port);
    std::printf("[mitm-p3] presenting certificate: %s\n", cert_path);
    std::printf("[mitm-p3] point the victim here:  ./client 192.168.64.10 %d "
                "ca-cert.pem\n", listen_port);
    std::fflush(stdout);

    while (true) {
        int victim_fd = accept(listen_fd, nullptr, nullptr);
        if (victim_fd < 0)
            continue;
        handle_victim(victim_fd, server_ip, server_port, mode, cert, key);
    }

    EVP_PKEY_free(key);
    X509_free(cert);
    close(listen_fd);
    return 0;
}
