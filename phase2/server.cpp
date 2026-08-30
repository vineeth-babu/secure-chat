#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <map>
#include <sstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

const int PORT = 5000;
const int MAX_CLIENTS = 2;

// username -> socket
std::map<std::string, int> clients;

std::mutex clients_mutex;


// Send a complete line to a client
bool send_line(int client_fd, const std::string& message) {
    std::string data = message + "\n";

    size_t total_sent = 0;

    while (total_sent < data.size()) {
        ssize_t sent = send(
            client_fd,
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


// Receive one newline-terminated line
bool receive_line(int client_fd, std::string& line) {
    line.clear();

    char ch;

    while (true) {
        ssize_t received = recv(client_fd, &ch, 1, 0);

        if (received <= 0) {
            return false;
        }

        if (ch == '\n') {
            break;
        }

        line += ch;

        // Prevent an accidentally huge message
        if (line.size() > 4096) {
            return false;
        }
    }

    return true;
}


// Handle one connected client
void handle_client(int client_fd) {

    std::string username;

    // First message must be:
    // REGISTER|username
    std::string line;

    if (!receive_line(client_fd, line)) {
        close(client_fd);
        return;
    }

    if (line.rfind("REGISTER|", 0) != 0) {
        send_line(client_fd, "ERROR|Expected REGISTER");
        close(client_fd);
        return;
    }

    username = line.substr(9);

    if (username.empty()) {
        send_line(client_fd, "ERROR|Username cannot be empty");
        close(client_fd);
        return;
    }


    // Add client to the client map
    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        if (clients.size() >= MAX_CLIENTS) {
            send_line(client_fd, "ERROR|Server full");
            close(client_fd);
            return;
        }

        if (clients.count(username)) {
            send_line(client_fd, "ERROR|Username already exists");
            close(client_fd);
            return;
        }

        clients[username] = client_fd;
    }

    std::cout << "[CONNECT] " << username << std::endl;

    send_line(client_fd, "OK|Registered");


    // Receive messages from this client
    while (true) {

        if (!receive_line(client_fd, line)) {
            break;
        }

        // QUIT
        if (line == "QUIT") {
            break;
        }

        // WHO
        if (line == "WHO") {

            std::string response = "USERS|";

            {
                std::lock_guard<std::mutex> lock(clients_mutex);

                bool first = true;

                for (const auto& entry : clients) {
                    if (!first) {
                        response += ",";
                    }

                    response += entry.first;
                    first = false;
                }
            }

            send_line(client_fd, response);
            continue;
        }


        // MSG|recipient|message
        if (line.rfind("MSG|", 0) == 0) {

            size_t first_separator = line.find('|', 4);

            if (first_separator == std::string::npos) {
                send_line(client_fd, "ERROR|Invalid message format");
                continue;
            }

            std::string recipient =
                line.substr(4, first_separator - 4);

            std::string message =
                line.substr(first_separator + 1);


            int recipient_fd = -1;

            {
                std::lock_guard<std::mutex> lock(clients_mutex);

                auto it = clients.find(recipient);

                if (it != clients.end()) {
                    recipient_fd = it->second;
                }
            }


            if (recipient_fd == -1) {
                send_line(client_fd, "ERROR|User not online");
                continue;
            }


            // Log the plaintext message.
            // This is required for Phase 1 verification.
            std::cout
                << "[RELAY] "
                << username
                << " -> "
                << recipient
                << ": "
                << message
                << std::endl;


            // Forward the message to the recipient
            std::string forwarded =
                "FROM|" + username + "|" + message;

            send_line(recipient_fd, forwarded);

            continue;
        }


        // Unknown command
        send_line(client_fd, "ERROR|Unknown command");
    }


    // Remove client from map
    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        clients.erase(username);
    }

    std::cout << "[DISCONNECT] "
              << username
              << std::endl;

    close(client_fd);
}


int main() {

    // Create TCP socket
    int server_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server_fd < 0) {
        std::cerr << "Socket creation failed\n";
        return 1;
    }


    // Allow quick restart after server shutdown
    int opt = 1;

    setsockopt(
        server_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt)
    );


    // Configure server address
    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);


    // Bind
    if (bind(
            server_fd,
            reinterpret_cast<sockaddr*>(&server_addr),
            sizeof(server_addr)
        ) < 0) {

        std::cerr << "Bind failed\n";
        close(server_fd);
        return 1;
    }


    // Listen
    if (listen(server_fd, MAX_CLIENTS) < 0) {

        std::cerr << "Listen failed\n";
        close(server_fd);
        return 1;
    }


    std::cout
        << "Server listening on port "
        << PORT
        << "...\n";


    // Continuously accept clients
    while (true) {

        sockaddr_in client_addr{};
        socklen_t client_len =
            sizeof(client_addr);

        int client_fd = accept(
            server_fd,
            reinterpret_cast<sockaddr*>(&client_addr),
            &client_len
        );

        if (client_fd < 0) {
            std::cerr << "Accept failed\n";
            continue;
        }


        // Each client gets its own thread
        std::thread(
            handle_client,
            client_fd
        ).detach();
    }


    close(server_fd);

    return 0;
}
