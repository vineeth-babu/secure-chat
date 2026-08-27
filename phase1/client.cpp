#include <iostream>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    const char* SERVER_IP = "192.168.64.2";
    const int PORT = 5000;

    // 1. Create TCP socket
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_fd < 0) {
        std::cerr << "Socket creation failed\n";
        return 1;
    }

    // 2. Configure server address
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server address\n";
        close(client_fd);
        return 1;
    }

    // 3. Connect to server
    if (connect(client_fd,
                reinterpret_cast<sockaddr*>(&server_addr),
                sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed\n";
        close(client_fd);
        return 1;
    }

    std::cout << "Connected to server!\n";

    // 4. Send a test message
    std::string message = "Hello from client1";

    send(client_fd, message.c_str(), message.size(), 0);

    std::cout << "Message sent: " << message << "\n";

    close(client_fd);

    return 0;
}
