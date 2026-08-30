/*
 * tamper_proxy.cpp -- CS6008 Phase 2 §3.2: tamper-detection demonstration
 *
 * A transparent TCP forwarder that sits between one client and the server and
 * flips a single bit in the ciphertext of one chosen record. Everything else
 * is passed through byte-for-byte.
 *
 * It needs no key and understands no cryptography. Both frame types used by
 * this project start with a 4-byte big-endian length, so the proxy can count
 * and modify frames without knowing whether a frame is a DH public value or
 * an encrypted record:
 *
 *     DH frame     [4-byte len = 256][256-byte public value]
 *     record       [4-byte len][8-byte counter][ciphertext][16-byte tag]
 *
 * Frame index 0 in each direction is the DH public value, so records start at
 * index 1. Byte 8 of a record body is the first ciphertext byte, which is
 * what gets flipped -- exactly the "modify a single byte of a captured
 * ciphertext" test the assignment asks for.
 *
 * Usage:
 *   ./tamper_proxy <listen_port> <server_ip> <server_port> <c2s|s2c> <frame#>
 *
 * Example (run on the client VM, or on the Mallory VM):
 *   ./tamper_proxy 6000 192.168.64.2 5000 s2c 2
 *   ./client 127.0.0.1 6000
 *
 * NOTE: this is a corruption test, not a man-in-the-middle attack. It cannot
 * read anything. Building the actual MITM proxy is the separate §3.3 task.
 */

#include "net.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

static const size_t MAX_FRAME = 65536;

struct Direction {
    const char *label;
    bool tamper_here;
    long tamper_frame;
};

/*
 * Forward length-prefixed frames from `in` to `out`, corrupting one byte of
 * the chosen frame if this direction is the one being tampered with.
 */
static void pump(int in, int out, Direction dir, std::atomic<bool> *running)
{
    long frame_index = 0;

    while (running->load()) {

        unsigned char hdr[4];
        if (!net::read_exact(in, hdr, 4))
            break;

        uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                       (static_cast<uint32_t>(hdr[1]) << 16) |
                       (static_cast<uint32_t>(hdr[2]) <<  8) |
                       (static_cast<uint32_t>(hdr[3]));

        if (len == 0 || len > MAX_FRAME) {
            std::printf("[proxy] %s: implausible frame length %u, stopping\n",
                        dir.label, len);
            break;
        }

        std::vector<unsigned char> body(len);
        if (!net::read_exact(in, body.data(), len))
            break;

        if (dir.tamper_here && frame_index == dir.tamper_frame) {

            /* Body layout of a record: [8-byte counter][ciphertext][tag].
               Offset 8 is the first ciphertext byte. */
            const size_t target = 8;

            if (len > target + 16) {
                unsigned char before = body[target];
                body[target] ^= 0x01;       /* flip exactly one bit */

                std::printf("[proxy] %s frame %ld: flipped one bit of "
                            "ciphertext byte %zu (0x%02X -> 0x%02X)\n",
                            dir.label, frame_index, target,
                            before, body[target]);
                std::fflush(stdout);
            } else {
                std::printf("[proxy] %s frame %ld too short to tamper "
                            "(len %u)\n", dir.label, frame_index, len);
            }
        }

        if (!net::write_all(out, hdr, 4) ||
            !net::write_all(out, body.data(), body.size()))
            break;

        frame_index++;
    }

    running->store(false);
    shutdown(in, SHUT_RDWR);
    shutdown(out, SHUT_RDWR);
}

int main(int argc, char *argv[])
{
    if (argc != 6) {
        std::fprintf(stderr,
            "usage: %s <listen_port> <server_ip> <server_port>"
            " <c2s|s2c> <frame_index>\n"
            "  frame 0 in each direction is the DH public value;\n"
            "  encrypted records start at frame 1.\n", argv[0]);
        return 1;
    }

    const int listen_port = std::atoi(argv[1]);
    const char *server_ip = argv[2];
    const int server_port = std::atoi(argv[3]);
    const std::string dirarg = argv[4];
    const long frame_index = std::atol(argv[5]);

    if (dirarg != "c2s" && dirarg != "s2c") {
        std::fprintf(stderr, "direction must be c2s or s2c\n");
        return 1;
    }

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

    if (listen(listen_fd, 1) < 0) {
        std::perror("listen");
        close(listen_fd);
        return 1;
    }

    std::printf("[proxy] listening on port %d, forwarding to %s:%d\n",
                listen_port, server_ip, server_port);
    std::printf("[proxy] will corrupt %s frame %ld\n",
                dirarg.c_str(), frame_index);
    std::fflush(stdout);

    while (true) {

        int client_fd = accept(listen_fd, nullptr, nullptr);
        if (client_fd < 0)
            continue;

        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            close(client_fd);
            continue;
        }

        sockaddr_in saddr{};
        saddr.sin_family = AF_INET;
        saddr.sin_port   = htons(static_cast<uint16_t>(server_port));
        inet_pton(AF_INET, server_ip, &saddr.sin_addr);

        if (connect(server_fd, reinterpret_cast<sockaddr *>(&saddr),
                    sizeof(saddr)) < 0) {
            std::perror("[proxy] connect to server");
            close(client_fd);
            close(server_fd);
            continue;
        }

        std::printf("[proxy] client connected, relaying\n");
        std::fflush(stdout);

        std::atomic<bool> running(true);

        Direction c2s{"c2s", dirarg == "c2s", frame_index};
        Direction s2c{"s2c", dirarg == "s2c", frame_index};

        std::thread up(pump, client_fd, server_fd, c2s, &running);
        std::thread down(pump, server_fd, client_fd, s2c, &running);

        up.join();
        down.join();

        close(client_fd);
        close(server_fd);

        std::printf("[proxy] session finished\n");
        std::fflush(stdout);
    }

    close(listen_fd);
    return 0;
}
