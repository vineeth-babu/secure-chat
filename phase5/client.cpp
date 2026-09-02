/*
 * client.cpp -- CS6008 Phase 2: chat client with DH + AES-256-GCM
 *
 * Command interface (assignment §1.3):
 *     @username message   send to username, and select username
 *     /chat username      select username without sending
 *     /who                list online users
 *     /quit               disconnect cleanly and exit
 *     anything else       sent as a plain chat message to the selected user
 *
 * Usage: ./client [connect-ip] [port] [ca-cert] [expected-server-ip]
 *   connect-ip           TCP destination (default 192.168.64.2)
 *   port                 TCP port (default 5000)
 *   ca-cert              trusted CA root PEM (default ca-cert.pem)
 *   expected-server-ip   identity to authenticate in the cert's IP SAN;
 *                        defaults to connect-ip. Set this separately only when
 *                        connecting through a proxy, to authenticate the REAL
 *                        server rather than the proxy's address.
 */

#include "dh.h"
#include "crypto.h"
#include "net.h"
#include "certs.h"
#include "e2e.h"

#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

static const char *DEFAULT_SERVER_IP = "192.168.64.2";
static const int   DEFAULT_PORT      = 5000;

/* ------------------------------------------------------------------ */
/* receiver thread                                                     */
/* ------------------------------------------------------------------ */

/*
 * Wrap one outgoing chat message for `recipient`.
 *
 * If a usable E2E session exists, the plaintext is sealed under the E2E key
 * and tagged __E2E_MSG__ BEFORE being handed to the existing outer
 * SecureChannel -- an additional inner layer, never a replacement. Otherwise
 * the Phase 3 plaintext behaviour is unchanged.
 *
 * Both outgoing paths (@user and the selected-partner fallback) go through
 * this one function so the E2E decision cannot diverge between them.
 */
/*
 * Phase 5 evidence line (§6.2): printed on BOTH clients every time a new E2E
 * key is installed, so a screenshot shows the fingerprints changing and the
 * two peers agreeing. Only the fingerprint is printed -- never key material.
 */
static void log_rotation(e2e::E2EManager *mgr, const std::string &peer)
{
    std::time_t now = std::time(nullptr);
    char stamp[32] = {0};
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S",
                  std::localtime(&now));

    std::cout << "\n[E2E-ROTATE] " << stamp
              << " peer=" << peer
              << " rotation=#" << mgr->rotation_count_of(peer)
              << " fingerprint=" << mgr->fingerprint_of(peer) << "\n> ";
    std::cout.flush();
}

/*
 * Phase 5 rekey timer (§6.1): ONE thread for the whole client, not one per
 * peer. It wakes once a second, asks the manager which sessions are due, and
 * re-runs exactly the same handshake /e2e uses -- no separate rotation
 * protocol and no new wire tags.
 *
 * peers_due_for_rotation() excludes peers with a handshake already pending,
 * so a rotation can never be started twice for the same peer. The manager and
 * SecureChannel both do their own locking, so this thread shares them with
 * the input and receive threads without any additional synchronisation.
 */
static void rekey_timer(int socket_fd,
                        crypto::SecureChannel *ch,
                        e2e::E2EManager *mgr,
                        std::atomic<bool> *running)
{
    const int ROTATE_SECONDS = 60;      /* fixed by the assignment (§6.1) */

    while (running->load()) {
        /* One-second granularity keeps shutdown responsive. */
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!running->load())
            break;

        for (const std::string &peer : mgr->peers_due_for_rotation(ROTATE_SECONDS)) {
            std::string init;
            if (mgr->start(peer, init) != e2e::Result::Ok)
                continue;               /* leaves the working key untouched */

            if (!ch->send_msg(socket_fd, "MSG|" + peer + "|" + init)) {
                /* Connection is going away; the receive thread reports it. */
                return;
            }

            std::cout << "\n[E2E] Rotating key with " << peer
                      << " (60s timer)...\n> ";
            std::cout.flush();
        }
    }
}

/*
 * RETURN CONTRACT: the bool means "the connection is still usable", NOT
 * "the message was sent". The caller uses it solely to decide whether to
 * abort the chat loop, so a purely local failure (e.g. an oversized E2E
 * payload) reports the error to the user and returns true -- the session is
 * fine, only this one message was dropped. Only a transport failure on the
 * outer SecureChannel returns false.
 *
 * CRITICAL: once an E2E session exists there is NO plaintext fallback. If
 * sealing fails the message is dropped, never sent in the clear.
 */
static bool send_chat(int fd, crypto::SecureChannel *ch,
                      e2e::E2EManager *mgr,
                      const std::string &recipient,
                      const std::string &text)
{
    unsigned char key[e2e::KEY_BYTES];

    if (mgr->get_key(recipient, key)) {
        std::string blob;
        bool sealed = e2e::seal(key, text, blob);
        OPENSSL_cleanse(key, sizeof(key));

        if (!sealed) {
            std::cout << "[E2E] Message too long for an E2E payload (max "
                      << e2e::MAX_E2E_PLAINTEXT << " bytes). Not sent.\n";
            /* Dropped, never downgraded to plaintext. Connection is fine. */
            return true;
        }

        return ch->send_msg(fd, "MSG|" + recipient + "|" +
                                std::string(e2e::TAG_MSG) + blob);
    }

    /* No E2E session: unchanged Phase 3 behaviour. */
    return ch->send_msg(fd, "MSG|" + recipient + "|" + text);
}

static void receive_messages(int socket_fd,
                             crypto::SecureChannel *ch,
                             e2e::E2EManager *mgr,
                             std::atomic<bool> *running)
{
    std::string line;

    while (running->load()) {

        crypto::RecvResult r = ch->recv_msg(socket_fd, line);

        if (r != crypto::RecvResult::Ok) {

            if (running->load()) {
                switch (r) {
                case crypto::RecvResult::AuthFailure:
                    std::cout << "\n[SECURITY] AES-GCM authentication FAILED."
                                 " A record was modified in transit"
                                 " (or replayed/forged).\n"
                                 "[SECURITY] The message was NOT decrypted."
                                 " Aborting the connection.\n";
                    break;
                case crypto::RecvResult::ProtocolError:
                    std::cout << "\n[SECURITY] Malformed record (bad length or"
                                 " out-of-sequence counter)."
                                 " Aborting the connection.\n";
                    break;
                default:
                    std::cout << "\nDisconnected from server.\n";
                    break;
                }
                std::cout.flush();
            }

            running->store(false);
            /* Unblock the main thread, which is sitting in getline(). */
            shutdown(socket_fd, SHUT_RDWR);
            break;
        }

        /* Incoming chat message */
        if (line.rfind("FROM|", 0) == 0) {

            size_t separator = line.find('|', 5);

            if (separator != std::string::npos) {
                std::string sender  = line.substr(5, separator - 5);
                std::string message = line.substr(separator + 1);

                /* ---------- Phase 4: E2E control and data ----------
                   These are consumed here and MUST NOT fall through to
                   ordinary chat display (assignment §1.4). */

                if (message.rfind(e2e::TAG_INIT, 0) == 0) {
                    std::string ack;
                    e2e::Result r = mgr->handle_init(sender, message, ack);

                    if (r == e2e::Result::Ok) {
                        /* Only report establishment if the ACK actually went
                           out. If the send fails the outer connection is
                           already broken and the session is ending, but we
                           must not print a misleading "established" line the
                           peer can never have seen. */
                        if (ch->send_msg(socket_fd,
                                         "MSG|" + sender + "|" + ack)) {
                            std::cout << "\n[E2E] Session with " << sender
                                      << " established (responder)."
                                      << "\n[E2E] Key fingerprint: "
                                      << mgr->fingerprint_of(sender) << "\n> ";
                            /* Phase 5 evidence line (also covers rotations,
                               since rotation reuses this same handshake). */
                            log_rotation(mgr, sender);
                        } else {
                            std::cout << "\n[E2E] Failed to send the E2E "
                                         "response to " << sender
                                      << " (connection problem).\n> ";
                        }
                    } else if (r == e2e::Result::GlareIgnored) {
                        /* Simultaneous /e2e: we won the tie-break, so we keep
                           our own handshake and send no ACK. */
                        std::cout << "\n[E2E] Simultaneous setup with "
                                  << sender << "; keeping our handshake "
                                     "(tie-break winner).\n> ";
                    } else {
                        std::cout << "\n[E2E] Rejected INIT from " << sender
                                  << ": " << e2e::result_str(r) << "\n> ";
                    }
                    std::cout.flush();
                    continue;
                }

                if (message.rfind(e2e::TAG_ACK, 0) == 0) {
                    e2e::Result r = mgr->handle_ack(sender, message);

                    if (r == e2e::Result::Ok) {
                        std::cout << "\n[E2E] Session with " << sender
                                  << " established (initiator)."
                                  << "\n[E2E] Key fingerprint: "
                                  << mgr->fingerprint_of(sender) << "\n> ";
                        log_rotation(mgr, sender);
                    } else {
                        std::cout << "\n[E2E] Rejected ACK from " << sender
                                  << ": " << e2e::result_str(r) << "\n> ";
                    }
                    std::cout.flush();
                    continue;
                }

                if (message.rfind(e2e::TAG_MSG, 0) == 0) {

                    if (!mgr->is_established(sender)) {
                        std::cout << "\n[E2E] Encrypted message from "
                                  << sender << " but no E2E session exists. "
                                     "Discarded.\n> ";
                        std::cout.flush();
                        continue;
                    }

                    /* Phase 5: tries the current key first and, only if that
                       fails authentication, the one-generation transition
                       key -- so a message still in flight from just before a
                       rotation remains readable (§6.1). */
                    std::string plain;
                    bool ok = mgr->open_for_peer(
                        sender, message.substr(std::strlen(e2e::TAG_MSG)),
                        plain);

                    if (!ok) {
                        /* Never show ciphertext, never show partial data. */
                        std::cout << "\n[E2E] AES-GCM authentication FAILED "
                                     "on a message from " << sender
                                  << ". Message discarded.\n> ";
                        std::cout.flush();
                        continue;
                    }

                    std::cout << "\n" << sender << ": " << plain << "\n> ";
                    std::cout.flush();
                    continue;
                }

                /* ---------- ordinary Phase 3 chat ---------- */
                std::cout << "\n" << sender << ": " << message << "\n> ";
                std::cout.flush();
            }

            continue;
        }

        std::cout << "\nServer: " << line << "\n> ";
        std::cout.flush();
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char *server_ip = (argc > 1) ? argv[1] : DEFAULT_SERVER_IP;
    const int   port      = (argc > 2) ? std::atoi(argv[2]) : DEFAULT_PORT;
    /* Phase 3: trusted CA root. Defaults to ./ca-cert.pem; override as argv[3].
       This is loaded from local disk and never from the network. */
    const char *ca_path   = (argc > 3) ? argv[3] : "ca-cert.pem";
    /* Phase 3: the server identity the client authenticates (the IP that must
       appear in the certificate's IP SAN). This is DELIBERATELY separate from
       the TCP destination: normally they are the same, but when connecting
       through a proxy the client still authenticates the REAL server's
       identity, not the proxy's address. Defaults to the connect IP, so
       ordinary usage is unchanged; override as argv[4] for proxy testing. */
    const char *expected_ip = (argc > 4) ? argv[4] : server_ip;

    std::string username;
    std::cout << "Enter username: ";

    if (!std::getline(std::cin, username) || username.empty()) {
        std::cerr << "A username is required\n";
        return 1;
    }

    /* ---------- connect ---------- */

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_fd < 0) {
        std::cerr << "Socket creation failed\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server address: " << server_ip << "\n";
        close(client_fd);
        return 1;
    }

    if (connect(client_fd, reinterpret_cast<sockaddr *>(&server_addr),
                sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed\n";
        close(client_fd);
        return 1;
    }

    std::cout << "Connected to " << server_ip << ":" << port << "\n";
    if (std::strcmp(expected_ip, server_ip) != 0) {
        std::cout << "Authenticating server identity " << expected_ip
                  << " (TCP destination " << server_ip
                  << " is a different host -- e.g. a proxy).\n";
    }

    /* ---------- Phase 3: authenticate the server BEFORE any DH ---------- */

    std::string auth_why;

    X509_STORE *ca_store = certs::load_ca_store(ca_path, &auth_why);
    if (ca_store == nullptr) {
        std::cerr << "Cannot load trusted CA (" << ca_path << "): "
                  << auth_why << "\n";
        close(client_fd);
        return 1;
    }

    std::cout << "Validating server certificate and proof-of-possession...\n";
    std::cout.flush();

    if (!certs::client_verify_auth(client_fd, ca_store, expected_ip, &auth_why)) {
        /* §4.1: on ANY validation failure the client aborts immediately and
           does not proceed to DH or reveal a username. */
        std::cerr << "[AUTH] server authentication FAILED: " << auth_why
                  << "\n[AUTH] Aborting before DH. No data was sent.\n";
        X509_STORE_free(ca_store);
        close(client_fd);
        return 1;
    }

    X509_STORE_free(ca_store);
    std::cout << "[AUTH] Server certificate valid and private-key possession "
                 "proven.\n";
    std::cout.flush();

    /* ---------- Diffie-Hellman ---------- */

    std::cout << "Performing Diffie-Hellman key exchange "
                 "(RFC 3526 group 14, 2048-bit)...\n";
    std::cout.flush();

    unsigned char shared[dh::PUB_BYTES];
    std::string why;

    if (!dh::run_handshake(client_fd, shared, &why)) {
        std::cerr << "DH key exchange failed: " << why << "\n";
        OPENSSL_cleanse(shared, sizeof(shared));
        close(client_fd);
        return 1;
    }

    unsigned char key[crypto::KEY_BYTES];
    crypto::derive_key(shared, sizeof(shared), key);
    OPENSSL_cleanse(shared, sizeof(shared));    /* raw secret, done with it */

    /* Fingerprint only: never the private exponent, raw secret or key. */
    std::cout << "Key established. Fingerprint: "
              << crypto::fingerprint(key) << "\n"
              << "(this must match the fingerprint printed by the server "
                 "for this connection)\n";

    crypto::SecureChannel ch;
    ch.init(key, crypto::Role::Client);
    OPENSSL_cleanse(key, sizeof(key));

    /* ---------- registration (encrypted) ---------- */

    if (!ch.send_msg(client_fd, "REGISTER|" + username)) {
        std::cerr << "Failed to send registration\n";
        close(client_fd);
        return 1;
    }

    std::string response;

    if (ch.recv_msg(client_fd, response) != crypto::RecvResult::Ok) {
        std::cerr << "Server disconnected during registration\n";
        close(client_fd);
        return 1;
    }

    std::cout << "Server: " << response << "\n";

    if (response != "OK|Registered") {
        close(client_fd);
        return 1;
    }

    /* ---------- chat ---------- */

    /* Phase 4: per-peer E2E sessions. Constructed with our own username so
       the glare rule can be evaluated deterministically. Shared between this
       (input) thread and the receiver thread; E2EManager does its own
       locking and never hands out references to internal state. */
    e2e::E2EManager e2e_mgr(username);

    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, client_fd, &ch, &e2e_mgr, &running);

    /* Phase 5: single rekey timer for all peers (§6.1, 60-second rotation). */
    std::thread rekeyer(rekey_timer, client_fd, &ch, &e2e_mgr, &running);

    /* §1.3: the currently selected chat partner. */
    std::string selected;

    std::cout << "Commands: @user msg | /chat user | /e2e user | /who | /quit\n";

    while (running.load()) {

        std::cout << "> ";
        std::cout.flush();

        std::string input;

        if (!std::getline(std::cin, input))
            break;

        if (!running.load())
            break;

        if (input.empty())
            continue;

        /* /quit */
        if (input == "/quit") {
            ch.send_msg(client_fd, "QUIT");
            running.store(false);
            shutdown(client_fd, SHUT_RDWR);
            break;
        }

        /* /who */
        if (input == "/who") {
            if (!ch.send_msg(client_fd, "WHO")) {
                std::cout << "Failed to send.\n";
                break;
            }
            continue;
        }

        /* /e2e username -- start an end-to-end key exchange (§1.3) */
        if (input == "/e2e" || input.rfind("/e2e ", 0) == 0) {

            std::string target = (input.size() > 5) ? input.substr(5) : "";

            while (!target.empty() && target.front() == ' ')
                target.erase(target.begin());
            while (!target.empty() && target.back() == ' ')
                target.pop_back();

            if (target.empty()) {
                std::cout << "Usage: /e2e username\n";
                continue;
            }

            if (target == username) {
                std::cout << "Cannot start an E2E session with yourself.\n";
                continue;
            }

            std::string init;
            e2e::Result r = e2e_mgr.start(target, init);

            if (r != e2e::Result::Ok) {
                std::cout << "[E2E] Could not start session with " << target
                          << ": " << e2e::result_str(r) << "\n";
                continue;
            }

            if (!ch.send_msg(client_fd, "MSG|" + target + "|" + init)) {
                std::cout << "Failed to send.\n";
                break;
            }

            std::cout << "[E2E] Key exchange initiated with " << target
                      << "; awaiting response...\n";
            continue;
        }

        /* /chat username -- switch partner without sending */
        if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);

            /* trim surrounding spaces */
            while (!target.empty() && target.front() == ' ')
                target.erase(target.begin());
            while (!target.empty() && target.back() == ' ')
                target.pop_back();

            if (target.empty()) {
                std::cout << "Usage: /chat username\n";
                continue;
            }

            selected = target;
            std::cout << "Now chatting with " << selected << "\n";
            continue;
        }

        /* @username message -- send and select */
        if (input[0] == '@') {
            size_t space = input.find(' ');

            if (space == std::string::npos) {
                std::cout << "Usage: @username message\n";
                continue;
            }

            std::string recipient = input.substr(1, space - 1);
            std::string message   = input.substr(space + 1);

            if (recipient.empty() || message.empty()) {
                std::cout << "Usage: @username message\n";
                continue;
            }

            selected = recipient;

            /* E2E-wrapped when a session exists, plaintext otherwise. */
            if (!send_chat(client_fd, &ch, &e2e_mgr, recipient, message)) {
                std::cout << "Failed to send.\n";
                break;
            }

            continue;
        }

        /*
         * §1.3: "Any input that does not match one of the recognized command
         * tags should be treated as a plain chat message to whichever user is
         * currently selected."
         */
        if (selected.empty()) {
            std::cout << "No chat partner selected. "
                         "Use @username message or /chat username.\n";
            continue;
        }

        if (!send_chat(client_fd, &ch, &e2e_mgr, selected, input)) {
            std::cout << "Failed to send.\n";
            break;
        }
    }

    running.store(false);
    shutdown(client_fd, SHUT_RDWR);

    if (receiver.joinable())
        receiver.join();

    /* Joined BEFORE the socket is closed, so the timer can never write to a
       closed or reused descriptor. */
    if (rekeyer.joinable())
        rekeyer.join();

    close(client_fd);
    return 0;
}
