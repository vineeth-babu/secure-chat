/*
 * e2e.cpp - Implementation of E2E crypto primitives and session manager.
 * Includes Base64 encode/decode, AES-256-GCM authenticated encryption,
 * DH session handshake handling, and automatic key rotation.
 */

#include "e2e.h"
#include "dh.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>

namespace e2e {

static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Map ASCII char back to 6-bit index (-1 if invalid)
static signed char b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return static_cast<signed char>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<signed char>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<signed char>(c - '0' + 52);
    if (c == '+')             return 62;
    if (c == '/')             return 63;
    return -1;
}

std::string base64_encode(const unsigned char *data, size_t len)
{
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;

    // Convert 3-byte blocks into 4 Base64 characters
    for (; i + 2 < len; i += 3) {
        uint32_t v = (static_cast<uint32_t>(data[i])     << 16) |
                     (static_cast<uint32_t>(data[i + 1]) <<  8) |
                     (static_cast<uint32_t>(data[i + 2]));
        out += B64_ALPHABET[(v >> 18) & 0x3F];
        out += B64_ALPHABET[(v >> 12) & 0x3F];
        out += B64_ALPHABET[(v >>  6) & 0x3F];
        out += B64_ALPHABET[(v      ) & 0x3F];
    }

    // Pad remaining 1 or 2 bytes with '='
    if (i < len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        bool two = (i + 1 < len);
        if (two)
            v |= static_cast<uint32_t>(data[i + 1]) << 8;

        out += B64_ALPHABET[(v >> 18) & 0x3F];
        out += B64_ALPHABET[(v >> 12) & 0x3F];
        out += two ? B64_ALPHABET[(v >> 6) & 0x3F] : '=';
        out += '=';
    }

    return out;
}

bool base64_decode(const std::string &text, std::vector<unsigned char> &out)
{
    out.clear();

    const size_t n = text.size();

    // Valid Base64 string must have length divisible by 4
    if (n == 0)
        return true;
    if (n % 4 != 0)
        return false;

    // Check padding format
    size_t pad = 0;
    if (text[n - 1] == '=') pad++;
    if (n >= 2 && text[n - 2] == '=') pad++;
    if (pad > 2)
        return false;

    out.reserve((n / 4) * 3);

    for (size_t i = 0; i < n; i += 4) {

        signed char c0 = b64_value(static_cast<unsigned char>(text[i]));
        signed char c1 = b64_value(static_cast<unsigned char>(text[i + 1]));

        if (c0 < 0 || c1 < 0)
            return false;

        const bool last_group = (i + 4 == n);

        signed char c2;
        signed char c3;

        if (last_group && pad > 0) {
            if (pad == 2) {
                if (text[i + 2] != '=' || text[i + 3] != '=')
                    return false;

                // Unused bits in c1 must be 0 to avoid malleability
                if ((c1 & 0x0F) != 0)
                    return false;

                out.push_back(static_cast<unsigned char>(
                    (c0 << 2) | (c1 >> 4)));
                continue;
            }

            // pad == 1
            c2 = b64_value(static_cast<unsigned char>(text[i + 2]));
            if (c2 < 0 || text[i + 3] != '=')
                return false;

            // Unused bits in c2 must be 0
            if ((c2 & 0x03) != 0)
                return false;

            out.push_back(static_cast<unsigned char>((c0 << 2) | (c1 >> 4)));
            out.push_back(static_cast<unsigned char>(
                ((c1 & 0x0F) << 4) | (c2 >> 2)));
            continue;
        }

        c2 = b64_value(static_cast<unsigned char>(text[i + 2]));
        c3 = b64_value(static_cast<unsigned char>(text[i + 3]));
        if (c2 < 0 || c3 < 0)
            return false;

        out.push_back(static_cast<unsigned char>((c0 << 2) | (c1 >> 4)));
        out.push_back(static_cast<unsigned char>(
            ((c1 & 0x0F) << 4) | (c2 >> 2)));
        out.push_back(static_cast<unsigned char>(
            ((c2 & 0x03) << 6) | c3));
    }

    return true;
}

// Encrypt plaintext and return base64 blob containing [nonce || ciphertext || tag]
bool seal(const unsigned char key[KEY_BYTES],
          const std::string &plaintext,
          std::string &out_b64)
{
    if (plaintext.size() > MAX_E2E_PLAINTEXT)
        return false;

    const size_t ptlen = plaintext.size();

    std::vector<unsigned char> blob(NONCE_BYTES + ptlen + TAG_BYTES);

    unsigned char *nonce = blob.data();
    unsigned char *ct    = blob.data() + NONCE_BYTES;
    unsigned char *tag   = ct + ptlen;

    // Generate random 12-byte nonce
    if (RAND_bytes(nonce, static_cast<int>(NONCE_BYTES)) != 1)
        return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return false;

    bool ok = false;
    int outl = 0;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(NONCE_BYTES), nullptr) != 1)
            break;

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
            break;

        if (ptlen > 0) {
            if (EVP_EncryptUpdate(ctx, ct, &outl,
                                  reinterpret_cast<const unsigned char *>(
                                      plaintext.data()),
                                  static_cast<int>(ptlen)) != 1)
                break;
            if (static_cast<size_t>(outl) != ptlen)
                break;
        }

        int finl = 0;
        if (EVP_EncryptFinal_ex(ctx, ct + ptlen, &finl) != 1 || finl != 0)
            break;

        // Retrieve the 16-byte auth tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(TAG_BYTES), tag) != 1)
            break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        OPENSSL_cleanse(blob.data(), blob.size());
        return false;
    }

    out_b64 = base64_encode(blob.data(), blob.size());
    OPENSSL_cleanse(blob.data(), blob.size());
    return true;
}

// Decrypt and verify base64 blob containing [nonce || ciphertext || tag]
bool open(const unsigned char key[KEY_BYTES],
          const std::string &in_b64,
          std::string &out_plaintext)
{
    out_plaintext.clear();

    std::vector<unsigned char> blob;

    if (!base64_decode(in_b64, blob))
        return false;

    if (blob.size() < NONCE_BYTES + TAG_BYTES)
        return false;

    const size_t ctlen = blob.size() - NONCE_BYTES - TAG_BYTES;

    if (ctlen > MAX_E2E_PLAINTEXT)
        return false;

    const unsigned char *nonce = blob.data();
    const unsigned char *ct    = blob.data() + NONCE_BYTES;
    const unsigned char *tag   = ct + ctlen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return false;

    std::vector<unsigned char> pt(ctlen + 1);

    bool ok = false;
    int outl = 0;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(NONCE_BYTES), nullptr) != 1)
            break;

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
            break;

        if (ctlen > 0) {
            if (EVP_DecryptUpdate(ctx, pt.data(), &outl,
                                  ct, static_cast<int>(ctlen)) != 1)
                break;
            if (static_cast<size_t>(outl) != ctlen)
                break;
        }

        // Set tag before finalizing
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                static_cast<int>(TAG_BYTES),
                                const_cast<unsigned char *>(tag)) != 1)
            break;

        int finl = 0;
        // Verify authentication tag
        if (EVP_DecryptFinal_ex(ctx, pt.data() + ctlen, &finl) <= 0)
            break;

        if (finl != 0)
            break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        OPENSSL_cleanse(pt.data(), pt.size());
        return false;
    }

    out_plaintext.assign(reinterpret_cast<const char *>(pt.data()), ctlen);
    OPENSSL_cleanse(pt.data(), pt.size());
    return true;
}

const char TAG_INIT[]        = "__E2E_INIT__";
const char TAG_ACK[]         = "__E2E_ACK__";
const char TAG_MSG[]         = "__E2E_MSG__";
const char E2E_KDF_CONTEXT[] = "CS6008-P4-E2E-v1";

const char *result_str(Result r)
{
    switch (r) {
    case Result::Ok:        return "ok";
    case Result::BadState:  return "illegal in current state";
    case Result::BadFormat: return "malformed payload";
    case Result::DhFailure: return "DH validation/derivation failed";
    case Result::Internal:  return "internal error";
    case Result::GlareIgnored:
        return "simultaneous INIT: ignored, we won the tie-break";
    }
    return "unknown";
}

namespace {

// Per-peer session tracking
struct Session {
    bool has_key = false;
    unsigned char key[KEY_BYTES] = {0};

    // Receive-only previous key retained during rotation transition
    bool has_prev = false;
    unsigned char prev_key[KEY_BYTES] = {0};

    // Rotation timing and counters
    std::chrono::steady_clock::time_point last_rotation{};
    unsigned long rotations = 0;

    // Stored pending keypair awaiting peer ACK
    std::unique_ptr<dh::KeyPair> pending;

    void wipe_key() { OPENSSL_cleanse(key, KEY_BYTES); has_key = false; }

    void wipe_prev() {
        OPENSSL_cleanse(prev_key, KEY_BYTES);
        has_prev = false;
    }

    // Demote current key to previous transition key when rotating to a new key
    void install(const unsigned char k[KEY_BYTES]) {
        if (has_key) {
            std::memcpy(prev_key, key, KEY_BYTES);
            has_prev = true;
        }
        std::memcpy(key, k, KEY_BYTES);
        has_key = true;

        last_rotation = std::chrono::steady_clock::now();
        rotations++;
    }

    State state() const {
        if (has_key)  return State::Established;
        if (pending)  return State::InitSent;
        return State::None;
    }

    void reset() {
        pending.reset();
        wipe_key();
        wipe_prev();
        rotations = 0;
    }
};

// Derive E2E key using domain separation string prepended to shared secret
bool derive_e2e_key(const unsigned char *Z, size_t zlen,
                    unsigned char key_out[KEY_BYTES])
{
    std::vector<unsigned char> input;
    input.reserve(sizeof(E2E_KDF_CONTEXT) - 1 + zlen);

    input.insert(input.end(), E2E_KDF_CONTEXT,
                 E2E_KDF_CONTEXT + sizeof(E2E_KDF_CONTEXT) - 1);
    input.insert(input.end(), Z, Z + zlen);

    crypto::derive_key(input.data(), input.size(), key_out);

    OPENSSL_cleanse(input.data(), input.size());
    return true;
}

// Compute first BIND_BYTES of SHA-256(initiator_public) to tie ACK to INIT
bool binding_digest(const unsigned char *pub, size_t publen,
                    unsigned char out[BIND_BYTES])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == nullptr)
        return false;

    bool ok = EVP_DigestInit_ex(md, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(md, pub, publen) == 1 &&
              EVP_DigestFinal_ex(md, digest, &dlen) == 1 &&
              dlen >= BIND_BYTES;

    EVP_MD_CTX_free(md);

    if (ok)
        std::memcpy(out, digest, BIND_BYTES);
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok;
}

// Parse wire tag and decode public key bytes
Result parse_pubvalue(const std::string &wire, const char *tag,
                      std::vector<unsigned char> &pub_out)
{
    const size_t taglen = std::strlen(tag);

    if (wire.size() <= taglen || wire.compare(0, taglen, tag) != 0)
        return Result::BadFormat;

    if (!base64_decode(wire.substr(taglen), pub_out))
        return Result::BadFormat;

    if (pub_out.size() != dh::PUB_BYTES)
        return Result::BadFormat;

    return Result::Ok;
}

// Parse ACK payload containing binding digest followed by public key
Result parse_ack(const std::string &wire,
                 std::vector<unsigned char> &bind_out,
                 std::vector<unsigned char> &pub_out)
{
    const size_t taglen = std::strlen(TAG_ACK);

    if (wire.size() <= taglen || wire.compare(0, taglen, TAG_ACK) != 0)
        return Result::BadFormat;

    std::vector<unsigned char> blob;
    if (!base64_decode(wire.substr(taglen), blob))
        return Result::BadFormat;

    if (blob.size() != BIND_BYTES + dh::PUB_BYTES)
        return Result::BadFormat;

    bind_out.assign(blob.begin(), blob.begin() + BIND_BYTES);
    pub_out.assign(blob.begin() + BIND_BYTES, blob.end());
    return Result::Ok;
}

}  // anonymous namespace

struct E2EManager::Impl {
    std::string self;
    std::mutex m;
    std::map<std::string, Session> peers;
    dh::Group group;
};

E2EManager::E2EManager(const std::string &self_username)
    : impl_(new Impl)
{
    impl_->self = self_username;
}

E2EManager::~E2EManager()
{
    {
        std::lock_guard<std::mutex> lock(impl_->m);
        for (auto &kv : impl_->peers)
            kv.second.reset();
    }
    delete impl_;
}

Result E2EManager::start(const std::string &peer, std::string &out_msg)
{
    std::lock_guard<std::mutex> lock(impl_->m);

    if (!impl_->group.ok())
        return Result::Internal;

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr)
        return Result::Internal;

    std::unique_ptr<dh::KeyPair> kp(new dh::KeyPair(impl_->group));

    unsigned char pub[dh::PUB_BYTES];
    Result rc = Result::Ok;

    if (!kp->generate(ctx))
        rc = Result::Internal;
    else if (!kp->public_bytes(pub))
        rc = Result::Internal;

    BN_CTX_free(ctx);

    if (rc != Result::Ok)
        return rc;

    out_msg = std::string(TAG_INIT) + base64_encode(pub, sizeof(pub));

    // Save pending keypair only after successful generation
    Session &s = impl_->peers[peer];
    s.pending = std::move(kp);

    OPENSSL_cleanse(pub, sizeof(pub));
    return Result::Ok;
}

Result E2EManager::handle_init(const std::string &peer,
                               const std::string &wire,
                               std::string &out_msg)
{
    std::vector<unsigned char> peer_pub;
    Result rc = parse_pubvalue(wire, TAG_INIT, peer_pub);
    if (rc != Result::Ok)
        return rc;

    std::lock_guard<std::mutex> lock(impl_->m);

    if (!impl_->group.ok())
        return Result::Internal;

    // Resolve simultaneous handshakes using lexicographical order of usernames
    {
        auto pit = impl_->peers.find(peer);
        const bool we_have_pending =
            (pit != impl_->peers.end() && pit->second.pending);

        if (we_have_pending && impl_->self < peer) {
            // Tie-break won: keep our handshake and ignore peer's INIT
            return Result::GlareIgnored;
        }
    }

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr)
        return Result::Internal;

    dh::KeyPair kp(impl_->group);
    unsigned char pub[dh::PUB_BYTES];
    unsigned char Z[dh::PUB_BYTES];
    unsigned char newkey[KEY_BYTES];
    std::string why;

    rc = Result::Ok;

    if (!kp.generate(ctx) || !kp.public_bytes(pub)) {
        rc = Result::Internal;
    } else if (!kp.compute_shared(peer_pub.data(), Z, ctx, &why)) {
        rc = Result::DhFailure;
    } else if (!derive_e2e_key(Z, sizeof(Z), newkey)) {
        rc = Result::Internal;
    }

    BN_CTX_free(ctx);
    OPENSSL_cleanse(Z, sizeof(Z));

    if (rc != Result::Ok) {
        OPENSSL_cleanse(newkey, sizeof(newkey));
        OPENSSL_cleanse(pub, sizeof(pub));
        return rc;
    }

    // Prepare ACK payload before updating local session state
    std::string ack_msg;
    {
        unsigned char bind[BIND_BYTES];
        if (!binding_digest(peer_pub.data(), peer_pub.size(), bind)) {
            OPENSSL_cleanse(newkey, sizeof(newkey));
            OPENSSL_cleanse(pub, sizeof(pub));
            return Result::Internal;
        }

        std::vector<unsigned char> payload;
        payload.reserve(BIND_BYTES + sizeof(pub));
        payload.insert(payload.end(), bind, bind + BIND_BYTES);
        payload.insert(payload.end(), pub, pub + sizeof(pub));

        ack_msg = std::string(TAG_ACK) +
                  base64_encode(payload.data(), payload.size());
    }

    // Install new key and clear pending handshake
    {
        Session &s = impl_->peers[peer];
        s.pending.reset();
        s.install(newkey);
    }

    out_msg = ack_msg;

    OPENSSL_cleanse(newkey, sizeof(newkey));
    OPENSSL_cleanse(pub, sizeof(pub));
    return Result::Ok;
}

Result E2EManager::handle_ack(const std::string &peer,
                              const std::string &wire)
{
    std::vector<unsigned char> bind_recv;
    std::vector<unsigned char> peer_pub;
    Result rc = parse_ack(wire, bind_recv, peer_pub);
    if (rc != Result::Ok)
        return rc;

    std::lock_guard<std::mutex> lock(impl_->m);

    auto it = impl_->peers.find(peer);
    if (it == impl_->peers.end() || !it->second.pending)
        return Result::BadState;

    Session &s = it->second;

    // Verify ACK corresponds to current pending handshake
    {
        unsigned char mine[dh::PUB_BYTES];
        unsigned char expect[BIND_BYTES];

        if (!s.pending->public_bytes(mine) ||
            !binding_digest(mine, sizeof(mine), expect)) {
            OPENSSL_cleanse(mine, sizeof(mine));
            return Result::Internal;
        }
        OPENSSL_cleanse(mine, sizeof(mine));

        if (bind_recv.size() != BIND_BYTES ||
            CRYPTO_memcmp(bind_recv.data(), expect, BIND_BYTES) != 0) {
            return Result::BadState;
        }
    }

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr)
        return Result::Internal;

    unsigned char Z[dh::PUB_BYTES];
    unsigned char newkey[KEY_BYTES];
    std::string why;

    rc = Result::Ok;

    if (!s.pending->compute_shared(peer_pub.data(), Z, ctx, &why))
        rc = Result::DhFailure;
    else if (!derive_e2e_key(Z, sizeof(Z), newkey))
        rc = Result::Internal;

    BN_CTX_free(ctx);
    OPENSSL_cleanse(Z, sizeof(Z));

    if (rc != Result::Ok) {
        OPENSSL_cleanse(newkey, sizeof(newkey));
        s.pending.reset();
        return rc;
    }

    // Install key and clear pending handshake
    s.install(newkey);
    s.pending.reset();

    OPENSSL_cleanse(newkey, sizeof(newkey));
    return Result::Ok;
}

State E2EManager::state_of(const std::string &peer)
{
    std::lock_guard<std::mutex> lock(impl_->m);
    auto it = impl_->peers.find(peer);
    return (it == impl_->peers.end()) ? State::None : it->second.state();
}

bool E2EManager::has_pending(const std::string &peer)
{
    std::lock_guard<std::mutex> lock(impl_->m);
    auto it = impl_->peers.find(peer);
    return it != impl_->peers.end() && it->second.pending != nullptr;
}

bool E2EManager::is_established(const std::string &peer)
{
    return state_of(peer) == State::Established;
}

bool E2EManager::get_key(const std::string &peer,
                         unsigned char key_out[KEY_BYTES])
{
    std::lock_guard<std::mutex> lock(impl_->m);
    auto it = impl_->peers.find(peer);
    if (it == impl_->peers.end() || !it->second.has_key)
        return false;
    std::memcpy(key_out, it->second.key, KEY_BYTES);
    return true;
}

std::string E2EManager::fingerprint_of(const std::string &peer)
{
    unsigned char key[KEY_BYTES];
    if (!get_key(peer, key))
        return std::string();
    std::string fp = crypto::fingerprint(key);
    OPENSSL_cleanse(key, sizeof(key));
    return fp;
}

bool E2EManager::open_for_peer(const std::string &peer,
                               const std::string &in_b64,
                               std::string &out_plaintext)
{
    // Copy active and transition keys under lock; decrypt outside lock
    unsigned char cur[KEY_BYTES];
    unsigned char prev[KEY_BYTES];
    bool have_cur = false, have_prev = false;

    {
        std::lock_guard<std::mutex> lock(impl_->m);
        auto it = impl_->peers.find(peer);
        if (it != impl_->peers.end()) {
            if (it->second.has_key) {
                std::memcpy(cur, it->second.key, KEY_BYTES);
                have_cur = true;
            }
            if (it->second.has_prev) {
                std::memcpy(prev, it->second.prev_key, KEY_BYTES);
                have_prev = true;
            }
        }
    }

    if (!have_cur) {
        OPENSSL_cleanse(prev, sizeof(prev));
        return false;
    }

    // Try decrypting with active key first
    bool ok = open(cur, in_b64, out_plaintext);

    // If active key fails, try previous key (handles messages sent during rotation)
    if (!ok && have_prev)
        ok = open(prev, in_b64, out_plaintext);

    OPENSSL_cleanse(cur, sizeof(cur));
    OPENSSL_cleanse(prev, sizeof(prev));
    return ok;
}

std::vector<std::string> E2EManager::peers_due_for_rotation(int seconds)
{
    std::vector<std::string> due;

    std::lock_guard<std::mutex> lock(impl_->m);
    const auto now = std::chrono::steady_clock::now();

    for (const auto &kv : impl_->peers) {
        const Session &s = kv.second;

        if (!s.has_key)
            continue;
        if (s.pending)
            continue;

        auto age = std::chrono::duration_cast<std::chrono::seconds>(
                       now - s.last_rotation).count();
        if (age >= seconds)
            due.push_back(kv.first);
    }

    return due;
}

unsigned long E2EManager::rotation_count_of(const std::string &peer)
{
    std::lock_guard<std::mutex> lock(impl_->m);
    auto it = impl_->peers.find(peer);
    return (it == impl_->peers.end()) ? 0 : it->second.rotations;
}

void E2EManager::clear(const std::string &peer)
{
    std::lock_guard<std::mutex> lock(impl_->m);
    auto it = impl_->peers.find(peer);
    if (it != impl_->peers.end()) {
        it->second.reset();
        impl_->peers.erase(it);
    }
}

}  // namespace e2e