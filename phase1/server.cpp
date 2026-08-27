#include <iostream>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    const int PORT = 5000;

    // Create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        std::cerr << "Socket creation failed\n";
        return 1;
    }

    std::cout << "Socket created successfully\n";

    // Configure server address
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(
            server_fd,
            reinterpret_cast<sockaddr*>(&server_addr),
            sizeof(server_addr)
        ) < 0) {

        std::cerr << "Bind failed\n";
        close(server_fd);
        return 1;
    }

    std::cout << "Server bound to port " << PORT << "\n";

    // Start listening
    if (listen(server_fd, 2) < 0) {
        std::cerr << "Listen failed\n";
        close(server_fd);
        return 1;
    }

    std::cout << "Server listening...\n";

    // Accept one client
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(
        server_fd,
        reinterpret_cast<sockaddr*>(&client_addr),
        &client_len
    );

    if (client_fd < 0) {
        std::cerr << "Accept failed\n";
        close(server_fd);
        return 1;
    }

    std::cout << "Client connected!\n";

    // Receive message
    char buffer[1024];

    ssize_t bytes_received = recv(
        client_fd,
        buffer,
        sizeof(buffer) - 1,
        0
    );

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';

        std::cout << "Received message: "
                  << buffer << "\n";
    }
    else if (bytes_received == 0) {
        std::cout << "Client disconnected.\n";
    }
    else {
        std::cerr << "Receive failed.\n";
    }

    close(client_fd);
    close(server_fd);

    return 0;
}
