#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace crypto {

constexpr size_t KEY_BYTES   = 32;   // AES-256 key size
constexpr size_t TAG_BYTES   = 16;   // GCM authentication tag
constexpr size_t NONCE_BYTES = 12;   // 96-bit GCM nonce

// Maximum size of one chat message
constexpr size_t MAX_PLAINTEXT = 4096;

// Sizes used in the encrypted record format
constexpr size_t HDR_BYTES      = 4;
constexpr size_t CTR_BYTES      = 8;
constexpr size_t MIN_BODY_BYTES = CTR_BYTES + TAG_BYTES;
constexpr size_t MAX_BODY_BYTES = CTR_BYTES + MAX_PLAINTEXT + TAG_BYTES;

enum class Role { Client, Server };

enum class RecvResult {
    Ok,
    Closed,         // Connection closed
    AuthFailure,    // Authentication check failed
    ProtocolError   // Invalid record or counter mismatch
};


// Derive the AES key from the Diffie-Hellman shared secret
void derive_key(const unsigned char *shared, size_t shared_len,
                unsigned char key_out[KEY_BYTES]);

// Generate a short fingerprint of the key for verification
std::string fingerprint(const unsigned char key[KEY_BYTES]);


class SecureChannel {
public:
    SecureChannel();
    ~SecureChannel();

    SecureChannel(const SecureChannel &) = delete;
    SecureChannel &operator=(const SecureChannel &) = delete;

    // Initialize the channel with the derived key and connection role
    void init(const unsigned char key[KEY_BYTES], Role role);

    // Encrypt and send one message
    bool send_msg(int fd, const std::string &plaintext);

    // Receive, verify and decrypt one message
    RecvResult recv_msg(int fd, std::string &plaintext_out);

private:
    unsigned char key_[KEY_BYTES];
    uint32_t send_dir_;
    uint32_t recv_dir_;
    uint64_t send_ctr_;
    uint64_t recv_ctr_;
    bool ready_;
    std::mutex send_mtx_;
};

}  // namespace crypto

#endif  // CRYPTO_H