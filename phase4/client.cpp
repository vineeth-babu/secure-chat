/*
 * Chat client implementation with end-to-end encryption.
 * Supports basic commands:
 *   @username <msg> - send to user and select them
 *   /chat <user>    - select active user
 *   /e2e <user>     - start key exchange
 *   /who            - list active users
 *   /quit           - disconnect
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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

static const char *DEFAULT_SERVER_IP = "192.168.64.2";
static const int   DEFAULT_PORT      = 5000;

// Helper to encrypt and send if an E2E session is active, otherwise send standard message.
// Returns false only if the underlying socket fails.
static bool send_chat(int fd, crypto::SecureChannel *ch,
                      e2e::E2EManager *mgr,
                      const std::string &recipient,
                      const std::string &text)
{
    unsigned char key[e2e::KEY_BYTES];

    // Check if we already have an active session with this recipient
    if (mgr->get_key(recipient, key)) {
        std::string blob;
        bool sealed = e2e::seal(key, text, blob);
        OPENSSL_cleanse(key, sizeof(key));

        if (!sealed) {
            std::cout << "[E2E] Message too long for an E2E payload (max "
                      << e2e::MAX_E2E_PLAINTEXT << " bytes). Not sent.\n";
            // Drop message rather than falling back to plaintext; connection is still valid
            return true;
        }

        return ch->send_msg(fd, "MSG|" + recipient + "|" +
                                std::string(e2e::TAG_MSG) + blob);
    }

    // Default: send regular message over outer secure channel
    return ch->send_msg(fd, "MSG|" + recipient + "|" + text);
}

// Background thread to handle incoming network traffic
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
            // Unblock main thread from getline()
            shutdown(socket_fd, SHUT_RDWR);
            break;
        }

        // Handle incoming chat messages
        if (line.rfind("FROM|", 0) == 0) {

            size_t separator = line.find('|', 5);

            if (separator != std::string::npos) {
                std::string sender  = line.substr(5, separator - 5);
                std::string message = line.substr(separator + 1);

                // Check for E2E control or encrypted data
                if (message.rfind(e2e::TAG_INIT, 0) == 0) {
                    std::string ack;
                    e2e::Result r = mgr->handle_init(sender, message, ack);

                    if (r == e2e::Result::Ok) {
                        if (ch->send_msg(socket_fd,
                                         "MSG|" + sender + "|" + ack)) {
                            std::cout << "\n[E2E] Session with " << sender
                                      << " established (responder)."
                                      << "\n[E2E] Key fingerprint: "
                                      << mgr->fingerprint_of(sender) << "\n> ";
                        } else {
                            std::cout << "\n[E2E] Failed to send the E2E "
                                         "response to " << sender
                                      << " (connection problem).\n> ";
                        }
                    } else if (r == e2e::Result::GlareIgnored) {
                        // Handled simultaneous handshake; tie-breaker won
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
                    } else {
                        std::cout << "\n[E2E] Rejected ACK from " << sender
                                  << ": " << e2e::result_str(r) << "\n> ";
                    }
                    std::cout.flush();
                    continue;
                }

                if (message.rfind(e2e::TAG_MSG, 0) == 0) {
                    unsigned char key[e2e::KEY_BYTES];

                    if (!mgr->get_key(sender, key)) {
                        std::cout << "\n[E2E] Encrypted message from "
                                  << sender << " but no E2E session exists. "
                                     "Discarded.\n> ";
                        std::cout.flush();
                        continue;
                    }

                    std::string plain;
                    bool ok = e2e::open(
                        key, message.substr(std::strlen(e2e::TAG_MSG)), plain);
                    OPENSSL_cleanse(key, sizeof(key));

                    if (!ok) {
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

                // Standard message display
                std::cout << "\n" << sender << ": " << message << "\n> ";
                std::cout.flush();
            }

            continue;
        }

        std::cout << "\nServer: " << line << "\n> ";
        std::cout.flush();
    }
}

int main(int argc, char *argv[])
{
    const char *server_ip = (argc > 1) ? argv[1] : DEFAULT_SERVER_IP;
    const int   port      = (argc > 2) ? std::atoi(argv[2]) : DEFAULT_PORT;
    const char *ca_path   = (argc > 3) ? argv[3] : "ca-cert.pem";
    // Allow separate IP check in case server is behind a proxy
    const char *expected_ip = (argc > 4) ? argv[4] : server_ip;

    std::string username;
    std::cout << "Enter username: ";

    if (!std::getline(std::cin, username) || username.empty()) {
        std::cerr << "A username is required\n";
        return 1;
    }

    // Set up socket connection
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

    // Authenticate server certificate
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

    // Diffie-Hellman handshake
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
    OPENSSL_cleanse(shared, sizeof(shared));

    std::cout << "Key established. Fingerprint: "
              << crypto::fingerprint(key) << "\n"
              << "(this must match the fingerprint printed by the server "
                 "for this connection)\n";

    crypto::SecureChannel ch;
    ch.init(key, crypto::Role::Client);
    OPENSSL_cleanse(key, sizeof(key));

    // Register user over encrypted channel
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

    // Set up chat session and start listener thread
    e2e::E2EManager e2e_mgr(username);

    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, client_fd, &ch, &e2e_mgr, &running);

    std::string selected;

    std::cout << "Commands: @user msg | /chat user | /e2e user | /who | /quit\n";

    // Main input loop
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

        // Quit command
        if (input == "/quit") {
            ch.send_msg(client_fd, "QUIT");
            running.store(false);
            shutdown(client_fd, SHUT_RDWR);
            break;
        }

        // Who command
        if (input == "/who") {
            if (!ch.send_msg(client_fd, "WHO")) {
                std::cout << "Failed to send.\n";
                break;
            }
            continue;
        }

        // Initiate E2E key exchange
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

        // Select partner without sending
        if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);

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

        // Direct message and select
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

            if (!send_chat(client_fd, &ch, &e2e_mgr, recipient, message)) {
                std::cout << "Failed to send.\n";
                break;
            }

            continue;
        }

        // Default: send to currently selected target
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

    // Clean up
    running.store(false);
    shutdown(client_fd, SHUT_RDWR);

    if (receiver.joinable())
        receiver.join();

    close(client_fd);
    return 0;
}