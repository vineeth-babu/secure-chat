/*
 * server.cpp -- CS6008 Phase 2: chat server with per-client DH + AES-256-GCM
 *
 * Application protocol is unchanged from Phase 1:
 *     REGISTER|username   ->  OK|Registered  /  ERROR|reason
 *     WHO                 ->  USERS|a,b
 *     MSG|recipient|text   ->  (relayed as) FROM|sender|text
 *     QUIT
 *
 * What Phase 2 changes: every one of those messages now travels inside an
 * authenticated encrypted record, including REGISTER (assignment §3.1 --
 * "not just chat messages but also any login/registration exchange").
 *
 * Each client gets its OWN independent DH exchange and therefore its own key
 * (§3.1). C1 <-> S and C2 <-> S share nothing.
 *
 * The server still decrypts and logs relayed messages, which is required for
 * the Phase 1/2 verification and is exactly the property Phase 4 removes.
 */

#include "dh.h"
#include "crypto.h"
#include "net.h"
#include "certs.h"

#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

static const int PORT        = 5000;
static const int MAX_CLIENTS = 2;

/* ------------------------------------------------------------------ */
/* per-connection state                                                */
/* ------------------------------------------------------------------ */

/*
 * One Session per connected client. Holds that client's own key and its own
 * send/receive counters -- this is what makes the two links independent.
 *
 * Held by shared_ptr: a thread relaying a message to another client copies
 * the pointer under the map lock, so the Session (and its fd) stays alive
 * even if the owner disconnects mid-relay. The fd is closed by the
 * destructor, i.e. when the last reference goes away, which removes the
 * classic "fd closed and reused while another thread writes to it" race.
 */
struct Session {
    int fd = -1;
    std::string username;
    crypto::SecureChannel ch;

    ~Session() {
        if (fd >= 0)
            close(fd);
    }
};

using SessionPtr = std::shared_ptr<Session>;

static std::map<std::string, SessionPtr> clients;   /* username -> session */
static std::mutex clients_mutex;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static std::string peer_string(const sockaddr_in &addr)
{
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
}

/* Report why a receive stopped, so a tampering test is unmistakable in the
   log rather than looking like an ordinary disconnect. */
static void log_recv_failure(const std::string &who, crypto::RecvResult r)
{
    switch (r) {
    case crypto::RecvResult::Closed:
        /* Ordinary hang-up. The single [DISCONNECT] line is printed by the
           teardown code, so nothing extra is needed here. */
        break;
    case crypto::RecvResult::AuthFailure:
        std::cout << "[SECURITY] " << who
                  << ": AES-GCM authentication FAILED -- record was modified,"
                     " replayed or forged. Aborting connection.\n";
        break;
    case crypto::RecvResult::ProtocolError:
        std::cout << "[SECURITY] " << who
                  << ": malformed record (bad length or out-of-sequence"
                     " counter). Aborting connection.\n";
        break;
    case crypto::RecvResult::Ok:
        break;
    }
    std::cout.flush();
}

/* ------------------------------------------------------------------ */
/* one client                                                          */
/* ------------------------------------------------------------------ */

static void handle_client(int fd, std::string peer,
                          X509 *srv_cert, EVP_PKEY *srv_key)
{
    /* The Session owns the fd from here on; its destructor closes it on
       every exit path below. */
    SessionPtr sess = std::make_shared<Session>();
    sess->fd = fd;

    /* ---------- Phase 3: prove our identity BEFORE any DH ---------- */

    std::string auth_why;
    if (!certs::server_send_auth(fd, srv_cert, srv_key, &auth_why)) {
        std::cout << "[AUTH-FAIL] " << peer << ": " << auth_why << "\n";
        std::cout.flush();
        return;     /* Session dtor closes fd */
    }

    /* ---------- 1. independent DH exchange for THIS connection ---------- */

    unsigned char shared[dh::PUB_BYTES];
    std::string why;

    if (!dh::run_handshake(fd, shared, &why)) {
        std::cout << "[DH-FAIL] " << peer << ": " << why << "\n";
        std::cout.flush();
        OPENSSL_cleanse(shared, sizeof(shared));
        return;
    }

    /* ---------- 2. derive the key by hashing the shared secret ---------- */

    unsigned char key[crypto::KEY_BYTES];
    crypto::derive_key(shared, sizeof(shared), key);

    /* The raw secret has done its job; wipe it immediately. */
    OPENSSL_cleanse(shared, sizeof(shared));

    /* Only the fingerprint is ever printed -- never the exponent, the raw
       secret or the key itself (§3.2). */
    std::cout << "[DH-OK] " << peer
              << "  key fingerprint: " << crypto::fingerprint(key) << "\n";
    std::cout.flush();

    sess->ch.init(key, crypto::Role::Server);
    OPENSSL_cleanse(key, sizeof(key));

    /* ---------- 3. everything from here on is encrypted ---------- */

    std::string line;
    crypto::RecvResult r = sess->ch.recv_msg(fd, line);

    if (r != crypto::RecvResult::Ok) {
        log_recv_failure(peer, r);
        return;
    }

    if (line.rfind("REGISTER|", 0) != 0) {
        sess->ch.send_msg(fd, "ERROR|Expected REGISTER");
        return;
    }

    std::string username = line.substr(9);

    if (username.empty()) {
        sess->ch.send_msg(fd, "ERROR|Username cannot be empty");
        return;
    }

    sess->username = username;

    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        if (clients.size() >= static_cast<size_t>(MAX_CLIENTS)) {
            /* Send outside the lock would be tidier, but the message is one
               small record and the lock is held only for this block. */
            sess->ch.send_msg(fd, "ERROR|Server full");
            return;
        }

        if (clients.count(username)) {
            sess->ch.send_msg(fd, "ERROR|Username already exists");
            return;
        }

        clients[username] = sess;
    }

    std::cout << "[CONNECT] " << username << " from " << peer << "\n";
    std::cout.flush();

    sess->ch.send_msg(fd, "OK|Registered");

    /* ---------- 4. message loop ---------- */

    while (true) {

        r = sess->ch.recv_msg(fd, line);

        if (r != crypto::RecvResult::Ok) {
            log_recv_failure(username, r);
            break;
        }

        /* QUIT */
        if (line == "QUIT")
            break;

        /* WHO */
        if (line == "WHO") {
            std::string response = "USERS|";

            {
                std::lock_guard<std::mutex> lock(clients_mutex);

                bool first = true;
                for (const auto &entry : clients) {
                    if (!first)
                        response += ",";
                    response += entry.first;
                    first = false;
                }
            }

            if (!sess->ch.send_msg(fd, response))
                break;

            continue;
        }

        /* MSG|recipient|message */
        if (line.rfind("MSG|", 0) == 0) {

            size_t first_separator = line.find('|', 4);

            if (first_separator == std::string::npos) {
                if (!sess->ch.send_msg(fd, "ERROR|Invalid message format"))
                    break;
                continue;
            }

            std::string recipient = line.substr(4, first_separator - 4);
            std::string message   = line.substr(first_separator + 1);

            SessionPtr target;

            {
                std::lock_guard<std::mutex> lock(clients_mutex);

                auto it = clients.find(recipient);
                if (it != clients.end())
                    target = it->second;    /* copy the shared_ptr */
            }

            if (!target) {
                if (!sess->ch.send_msg(fd, "ERROR|User not online"))
                    break;
                continue;
            }

            /*
             * The server can still read every relayed message: it holds both
             * link keys, so it decrypts on the way in and re-encrypts on the
             * way out. Required evidence for Phase 1/2, and exactly the
             * property Phase 4's end-to-end layer takes away.
             */
            std::cout << "[RELAY] " << username << " -> " << recipient
                      << ": " << message << "\n";
            std::cout.flush();

            std::string forwarded = "FROM|" + username + "|" + message;

            /* Encrypted under the RECIPIENT's key, with the recipient's own
               counter. SecureChannel::send_msg holds that session's send
               mutex, so this is safe even though we are on the sender's
               thread. */
            target->ch.send_msg(target->fd, forwarded);

            continue;
        }

        if (!sess->ch.send_msg(fd, "ERROR|Unknown command"))
            break;
    }

    /* ---------- 5. teardown ---------- */

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = clients.find(username);
        /* Only erase if the map still points at *this* session. */
        if (it != clients.end() && it->second == sess)
            clients.erase(it);
    }

    std::cout << "[DISCONNECT] " << username << "\n";
    std::cout.flush();

    /* sess goes out of scope here; the fd is closed by ~Session once no
       relaying thread still holds a reference. */
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    /* Phase 3: load the server certificate and its private key once, at
       startup. Defaults to ./server-cert.pem and ./server-key.pem; override
       as argv[1] and argv[2]. */
    const char *cert_path = (argc > 1) ? argv[1] : "server-cert.pem";
    const char *key_path  = (argc > 2) ? argv[2] : "server-key.pem";

    std::string cert_why;
    X509 *cert = certs::load_cert_file(cert_path, &cert_why);
    if (cert == nullptr) {
        std::cerr << "Cannot load server certificate: " << cert_why << "\n";
        return 1;
    }

    EVP_PKEY *key = certs::load_privkey_file(key_path, &cert_why);
    if (key == nullptr) {
        std::cerr << "Cannot load server private key: " << cert_why << "\n";
        X509_free(cert);
        return 1;
    }

    /* Fail fast if the operator paired a mismatched cert and key. */
    if (!certs::key_matches_cert(cert, key, &cert_why)) {
        std::cerr << "Configuration error: " << cert_why << "\n";
        EVP_PKEY_free(key);
        X509_free(cert);
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        std::cerr << "Socket creation failed\n";
        EVP_PKEY_free(key);
        X509_free(cert);
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;   /* all interfaces: required
                                                   for the multi-VM setup */
    server_addr.sin_port        = htons(PORT);

    if (bind(server_fd, reinterpret_cast<sockaddr *>(&server_addr),
             sizeof(server_addr)) < 0) {
        std::cerr << "Bind failed\n";
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, MAX_CLIENTS) < 0) {
        std::cerr << "Listen failed\n";
        close(server_fd);
        return 1;
    }

    std::cout << "Phase 3 server listening on port " << PORT << "\n"
              << "Sends its certificate and proves key possession before each "
                 "client's Diffie-Hellman exchange (RFC 3526 group 14).\n";
    std::cout.flush();

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd,
                               reinterpret_cast<sockaddr *>(&client_addr),
                               &client_len);

        if (client_fd < 0) {
            std::cerr << "Accept failed\n";
            continue;
        }

        std::thread(handle_client, client_fd,
                    peer_string(client_addr), cert, key).detach();
    }

    close(server_fd);
    return 0;
}
