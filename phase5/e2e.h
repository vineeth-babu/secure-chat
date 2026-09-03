/*
 * e2e.h - End-to-end encryption helpers and session management.
 * Handles in-memory AEAD (AES-256-GCM), Base64 encode/decode,
 * DH key exchange, and periodic session key rotation.
 */

#ifndef E2E_H
#define E2E_H

#include <cstddef>
#include <string>
#include <vector>

namespace e2e {

// Crypto buffer sizes
constexpr size_t KEY_BYTES   = 32;   // AES-256 key size
constexpr size_t NONCE_BYTES = 12;   // 96-bit nonce for GCM
constexpr size_t TAG_BYTES   = 16;   // 128-bit authentication tag

// Maximum plaintext size before Base64 expansion to prevent buffer overflow
constexpr size_t MAX_E2E_PLAINTEXT = 2048;

// Base64 encode helper
std::string base64_encode(const unsigned char *data, size_t len);

// Base64 decode helper. Returns false on invalid padding or characters.
bool base64_decode(const std::string &text, std::vector<unsigned char> &out);

// Encrypts plaintext into a base64 string containing: nonce + ciphertext + tag
bool seal(const unsigned char key[KEY_BYTES],
          const std::string &plaintext,
          std::string &out_b64);

// Decrypts and authenticates base64 blob containing: nonce + ciphertext + tag
bool open(const unsigned char key[KEY_BYTES],
          const std::string &in_b64,
          std::string &out_plaintext);

// Wire protocol message prefixes
extern const char TAG_INIT[];   // "__E2E_INIT__"
extern const char TAG_ACK[];    // "__E2E_ACK__"
extern const char TAG_MSG[];    // "__E2E_MSG__"

// Domain separation prefix for key derivation
extern const char E2E_KDF_CONTEXT[];   // "CS6008-P4-E2E-v1"

// Size of handshake binding prefix (first 8 bytes of SHA-256(initiator_public))
constexpr size_t BIND_BYTES = 8;

// Session handshake states
enum class State {
    None,           // No key established, no pending handshake
    InitSent,       // Sent INIT, waiting for ACK
    Established     // Active shared key established
};

// Status codes for handshake and crypto operations
enum class Result {
    Ok,
    BadState,       // Action not permitted in current state
    BadFormat,      // Malformed wire message or bad Base64
    DhFailure,      // Invalid public key or DH computation failed
    Internal,       // OpenSSL internal error
    GlareIgnored    // Simultaneous handshake: ignored peer INIT because our username won tie-break
};

const char *result_str(Result r);

// Manages thread-safe E2E sessions, keys, and rotation for all peers
class E2EManager {
public:
    // Takes local username to resolve simultaneous handshake tie-breaks
    explicit E2EManager(const std::string &self_username);
    ~E2EManager();

    E2EManager(const E2EManager &) = delete;
    E2EManager &operator=(const E2EManager &) = delete;

    // Start handshake: generates keypair and outputs INIT message to send
    Result start(const std::string &peer, std::string &out_msg);

    // Responder: handles peer INIT, derives shared key, and outputs ACK message
    Result handle_init(const std::string &peer, const std::string &wire,
                       std::string &out_msg);

    // Initiator: handles peer ACK and finalizes shared key
    Result handle_ack(const std::string &peer, const std::string &wire);

    // Get current handshake state with peer
    State state_of(const std::string &peer);

    // Returns true if a valid shared key exists
    bool  is_established(const std::string &peer);

    // Returns true if an outgoing handshake is currently awaiting an ACK
    bool  has_pending(const std::string &peer);

    // Copies established key into key_out; returns false if not established
    bool get_key(const std::string &peer, unsigned char key_out[KEY_BYTES]);

    // Returns hex fingerprint of the peer's current key
    std::string fingerprint_of(const std::string &peer);

    // Wipes session data and keys for a specific peer
    void clear(const std::string &peer);

    // Decrypt incoming message, falling back to previous key during rotation if needed
    bool open_for_peer(const std::string &peer,
                       const std::string &in_b64,
                       std::string &out_plaintext);

    // Returns list of peers ready for automatic key rotation
    std::vector<std::string> peers_due_for_rotation(int seconds);

    // Number of times the session key has rotated/installed
    unsigned long rotation_count_of(const std::string &peer);

private:
    struct Impl;
    Impl *impl_;
};

}  // namespace e2e

#endif // E2E_H