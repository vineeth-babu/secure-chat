#include "dh.h"
#include "crypto.h"
#include "net.h"

#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

static const char *DEFAULT_SERVER_IP = "192.168.64.2";
static const int   DEFAULT_PORT      = 5000;


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

            // Wake up the main thread if it is waiting for input
            shutdown(socket_fd, SHUT_RDWR);
            break;
        }

        // Display messages received from another user
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

        // Display other responses from the server
        std::cout << "\nServer: " << line << "\n> ";
        std::cout.flush();
    }
}


int main(int argc, char *argv[])
{
    const char *server_ip = (argc > 1) ? argv[1] : DEFAULT_SERVER_IP;
    const int   port      = (argc > 2) ? std::atoi(argv[2]) : DEFAULT_PORT;

    std::string username;
    std::cout << "Enter username: ";

    if (!std::getline(std::cin, username) || username.empty()) {
        std::cerr << "A username is required\n";
        return 1;
    }

    // Create and connect the TCP socket
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

    // Perform Diffie-Hellman key exchange
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

    // Derive the AES key from the shared secret
    unsigned char key[crypto::KEY_BYTES];
    crypto::derive_key(shared, sizeof(shared), key);
    OPENSSL_cleanse(shared, sizeof(shared));

    // Show only the fingerprint, not the actual key
    std::cout << "Key established. Fingerprint: "
              << crypto::fingerprint(key) << "\n"
              << "(this must match the fingerprint printed by the server "
                 "for this connection)\n";

    crypto::SecureChannel ch;
    ch.init(key, crypto::Role::Client);
    OPENSSL_cleanse(key, sizeof(key));

    // Register with the server through the encrypted channel
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

    // Start the thread that receives messages
    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, client_fd, &ch, &running);

    // Currently selected user for normal messages
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

        // Quit the chat
        if (input == "/quit") {
            ch.send_msg(client_fd, "QUIT");
            running.store(false);
            shutdown(client_fd, SHUT_RDWR);
            break;
        }

        // List online users
        if (input == "/who") {
            if (!ch.send_msg(client_fd, "WHO")) {
                std::cout << "Failed to send.\n";
                break;
            }
            continue;
        }

        // Select a user without sending a message
        if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);

            // Remove spaces around the username
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

        // Send a message and select that user
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

        // Send normal input to the currently selected user
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