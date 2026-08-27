#include <iostream>
#include <string>
#include <thread>
#include <atomic>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

const char* SERVER_IP = "192.168.64.2";
const int PORT = 5000;


bool send_line(int socket_fd, const std::string& message) {
    std::string data = message + "\n";

    size_t total_sent = 0;

    while (total_sent < data.size()) {

        ssize_t sent = send(
            socket_fd,
            data.c_str() + total_sent,
            data.size() - total_sent,
            0
        );

        if (sent <= 0) {
            return false;
        }

        total_sent += sent;
    }

    return true;
}


bool receive_line(int socket_fd, std::string& line) {

    line.clear();

    char ch;

    while (true) {

        ssize_t received =
            recv(socket_fd, &ch, 1, 0);

        if (received <= 0) {
            return false;
        }

        if (ch == '\n') {
            break;
        }

        line += ch;

        if (line.size() > 4096) {
            return false;
        }
    }

    return true;
}


// Continuously listen for messages from the server
void receive_messages(
    int socket_fd,
    std::atomic<bool>& running
) {

    std::string line;

    while (running) {

        if (!receive_line(socket_fd, line)) {
            running = false;
            break;
        }

        // Incoming chat message
        if (line.rfind("FROM|", 0) == 0) {

            size_t separator =
                line.find('|', 5);

            if (separator != std::string::npos) {

                std::string sender =
                    line.substr(5, separator - 5);

                std::string message =
                    line.substr(separator + 1);

                std::cout
                    << "\n"
                    << sender
                    << ": "
                    << message
                    << "\n> ";

                std::cout.flush();
            }

            continue;
        }

        // Other server messages
        std::cout
            << "\nServer: "
            << line
            << "\n> ";

        std::cout.flush();
    }
}


int main() {

    std::string username;

    std::cout << "Enter username: ";

    std::getline(
        std::cin,
        username
    );


    // Create TCP socket
    int client_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (client_fd < 0) {

        std::cerr
            << "Socket creation failed\n";

        return 1;
    }


    // Configure server address
    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);


    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &server_addr.sin_addr
        ) <= 0) {

        std::cerr
            << "Invalid server address\n";

        close(client_fd);

        return 1;
    }


    // Connect
    if (connect(
            client_fd,
            reinterpret_cast<sockaddr*>(&server_addr),
            sizeof(server_addr)
        ) < 0) {

        std::cerr
            << "Connection failed\n";

        close(client_fd);

        return 1;
    }


    std::cout
        << "Connected to server!\n";


    // Register
    if (!send_line(
            client_fd,
            "REGISTER|" + username
        )) {

        std::cerr
            << "Failed to register\n";

        close(client_fd);

        return 1;
    }


    // Receive registration response
    std::string response;

    if (!receive_line(
            client_fd,
            response
        )) {

        std::cerr
            << "Server disconnected\n";

        close(client_fd);

        return 1;
    }


    std::cout
        << "Server: "
        << response
        << "\n";


    if (response != "OK|Registered") {

        close(client_fd);

        return 1;
    }


    // Start receiver thread
    std::atomic<bool> running(true);

    std::thread receiver(
        receive_messages,
        client_fd,
        std::ref(running)
    );


    // Main input loop
    while (running) {

        std::cout << "> ";
        std::cout.flush();

        std::string input;

        if (!std::getline(
                std::cin,
                input
            )) {

            break;
        }


        // Quit
        if (input == "/quit") {

            send_line(
                client_fd,
                "QUIT"
            );

            running = false;

            shutdown(
                client_fd,
                SHUT_RDWR
            );

            break;
        }


        // WHO
        if (input == "/who") {

            send_line(
                client_fd,
                "WHO"
            );

            continue;
        }


        // @username message
        if (!input.empty() &&
            input[0] == '@') {

            size_t space =
                input.find(' ');

            if (space == std::string::npos) {

                std::cout
                    << "Usage: @username message\n";

                continue;
            }


            std::string recipient =
                input.substr(
                    1,
                    space - 1
                );

            std::string message =
                input.substr(
                    space + 1
                );


            if (recipient.empty() ||
                message.empty()) {

                std::cout
                    << "Usage: @username message\n";

                continue;
            }


            send_line(
                client_fd,
                "MSG|" +
                recipient +
                "|" +
                message
            );

            continue;
        }


        std::cout
            << "Unknown command. "
            << "Use @username message, "
            << "/who, or /quit.\n";
    }


    running = false;

    shutdown(
        client_fd,
        SHUT_RDWR
    );

    if (receiver.joinable()) {
        receiver.join();
    }

    close(client_fd);

    return 0;
}
