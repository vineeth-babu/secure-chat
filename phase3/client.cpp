

#include "dh.h"
#include "crypto.h"
#include "net.h"
#include "certs.h"

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

// receiver thread

static void receive_messages(int socket_fd,
                             crypto::SecureChannel *ch,
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
            // unblocks the main thread, which is sitting in getline()
            shutdown(socket_fd, SHUT_RDWR);
            break;
        }

        /* Incoming chat message */
        if (line.rfind("FROM|", 0) == 0) {

            size_t separator = line.find('|', 5);

            if (separator != std::string::npos) {
                std::string sender  = line.substr(5, separator - 5);
                std::string message = line.substr(separator + 1);

                std::cout << "\n" << sender << ": " << message << "\n> ";
                std::cout.flush();
            }

            continue;
        }

        std::cout << "\nServer: " << line << "\n> ";
        std::cout.flush();
    }
}

// main

int main(int argc, char *argv[])
{
    const char *server_ip = (argc > 1) ? argv[1] : DEFAULT_SERVER_IP;
    const int   port      = (argc > 2) ? std::atoi(argv[2]) : DEFAULT_PORT;
    // trusted CA root, defaults to ./ca-cert.pem, override with argv[3].
    // Loaded from local disk, never from the network.
    const char *ca_path   = (argc > 3) ? argv[3] : "ca-cert.pem";
    // the server identity we authenticate (must appear in the cert's IP
    // SAN). Kept separate from the TCP destination on purpose: normally
    // they're the same, but through a proxy we still want to authenticate
    // the real server, not the proxy's address. Defaults to connect_ip.
    const char *expected_ip = (argc > 4) ? argv[4] : server_ip;

    std::string username;
    std::cout << "Enter username: ";

    if (!std::getline(std::cin, username) || username.empty()) {
        std::cerr << "A username is required\n";
        return 1;
    }

    // connect

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

    // authenticate the server before any DH

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
        // on ANY validation failure we abort right away -- no DH, no
        // username sent
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

    // Diffie-Hellman

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

    // fingerprint only -- never the private exponent, raw secret or key
    std::cout << "Key established. Fingerprint: "
              << crypto::fingerprint(key) << "\n"
              << "(this must match the fingerprint printed by the server "
                 "for this connection)\n";

    crypto::SecureChannel ch;
    ch.init(key, crypto::Role::Client);
    OPENSSL_cleanse(key, sizeof(key));

    // registration (encrypted)

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

    // chat

    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, client_fd, &ch, &running);

    // the currently selected chat partner
    std::string selected;

    std::cout << "Commands: @user msg | /chat user | /who | /quit\n";

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

        // /quit
        if (input == "/quit") {
            ch.send_msg(client_fd, "QUIT");
            running.store(false);
            shutdown(client_fd, SHUT_RDWR);
            break;
        }

        // /who
        if (input == "/who") {
            if (!ch.send_msg(client_fd, "WHO")) {
                std::cout << "Failed to send.\n";
                break;
            }
            continue;
        }

        // /chat username -- switch partner without sending
        if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);

            // trim surrounding spaces
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

        // @username message -- send and select
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

            if (!ch.send_msg(client_fd,
                             "MSG|" + recipient + "|" + message)) {
                std::cout << "Failed to send.\n";
                break;
            }

            continue;
        }

        // anything that isn't one of the recognised commands is just a
        // plain chat message to whoever is currently selected
        if (selected.empty()) {
            std::cout << "No chat partner selected. "
                         "Use @username message or /chat username.\n";
            continue;
        }

        if (!ch.send_msg(client_fd, "MSG|" + selected + "|" + input)) {
            std::cout << "Failed to send.\n";
            break;
        }
    }

    running.store(false);
    shutdown(client_fd, SHUT_RDWR);

    if (receiver.joinable())
        receiver.join();

    close(client_fd);
    return 0;
}
