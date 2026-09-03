#include "crypto.h"
#include "net.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <arpa/inet.h>

#include <cstring>
#include <vector>

namespace crypto {

static void put_u32_be(unsigned char *p, uint32_t v)
{
    p[0] = static_cast<unsigned char>(v >> 24);
    p[1] = static_cast<unsigned char>(v >> 16);
    p[2] = static_cast<unsigned char>(v >>  8);
    p[3] = static_cast<unsigned char>(v);
}

static uint32_t get_u32_be(const unsigned char *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           (static_cast<uint32_t>(p[3]));
}

static void put_u64_be(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = static_cast<unsigned char>(v >> (56 - 8 * i));
}

static uint64_t get_u64_be(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

// Nonce contains a direction value and message counter
static void build_nonce(unsigned char nonce[NONCE_BYTES],
                        uint32_t dir, uint64_t ctr)
{
    put_u32_be(nonce, dir);
    put_u64_be(nonce + 4, ctr);
}


static const char KEY_LABEL[] = "CS6008-P2-KEY-v1";
static const char FP_LABEL[]  = "CS6008-P2-FP-v1";

static bool sha256_two(const void *a, size_t alen,
                       const void *b, size_t blen,
                       unsigned char out[32])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == nullptr)
        return false;

    bool ok = false;
    unsigned int outlen = 0;

    if (EVP_DigestInit_ex(md, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(md, a, alen) == 1 &&
        EVP_DigestUpdate(md, b, blen) == 1 &&
        EVP_DigestFinal_ex(md, out, &outlen) == 1 &&
        outlen == 32) {
        ok = true;
    }

    EVP_MD_CTX_free(md);
    return ok;
}

void derive_key(const unsigned char *shared, size_t shared_len,
                unsigned char key_out[KEY_BYTES])
{
    unsigned char digest[32];

    // Do not include the terminating null character in the label
    if (!sha256_two(KEY_LABEL, sizeof(KEY_LABEL) - 1,
                    shared, shared_len, digest)) {
        // Do not continue with an invalid key
        std::memset(key_out, 0, KEY_BYTES);
        return;
    }

    std::memcpy(key_out, digest, KEY_BYTES);
    OPENSSL_cleanse(digest, sizeof(digest));
}

std::string fingerprint(const unsigned char key[KEY_BYTES])
{
    unsigned char digest[32];

    if (!sha256_two(FP_LABEL, sizeof(FP_LABEL) - 1, key, KEY_BYTES, digest))
        return std::string("<fingerprint unavailable>");

    static const char *hexdigits = "0123456789ABCDEF";
    std::string out;

    // Show the first 8 bytes in a readable format
    for (int i = 0; i < 8; i++) {
        if (i > 0 && i % 2 == 0)
            out += ' ';
        out += hexdigits[digest[i] >> 4];
        out += hexdigits[digest[i] & 0x0F];
    }

    OPENSSL_cleanse(digest, sizeof(digest));
    return out;
}


SecureChannel::SecureChannel()
    : send_dir_(0), recv_dir_(0), send_ctr_(0), recv_ctr_(0), ready_(false)
{
    std::memset(key_, 0, sizeof(key_));
}

SecureChannel::~SecureChannel()
{
    OPENSSL_cleanse(key_, sizeof(key_));
}

void SecureChannel::init(const unsigned char key[KEY_BYTES], Role role)
{
    std::memcpy(key_, key, KEY_BYTES);

    // Use different values for each direction
    if (role == Role::Client) {
        send_dir_ = 1;
        recv_dir_ = 2;
    } else {
        send_dir_ = 2;
        recv_dir_ = 1;
    }

    send_ctr_ = 0;
    recv_ctr_ = 0;
    ready_    = true;
}

bool SecureChannel::send_msg(int fd, const std::string &plaintext)
{
    if (!ready_)
        return false;

    if (plaintext.size() > MAX_PLAINTEXT)
        return false;

    std::lock_guard<std::mutex> lock(send_mtx_);

    // Do not allow the counter to wrap and reuse a nonce
    if (send_ctr_ == UINT64_MAX)
        return false;

    const uint64_t ctr = send_ctr_;

    unsigned char nonce[NONCE_BYTES];
    build_nonce(nonce, send_dir_, ctr);

    unsigned char ctr_be[CTR_BYTES];
    put_u64_be(ctr_be, ctr);

    const size_t ptlen   = plaintext.size();
    const size_t bodylen = CTR_BYTES + ptlen + TAG_BYTES;

    std::vector<unsigned char> frame(HDR_BYTES + bodylen);
    put_u32_be(frame.data(), static_cast<uint32_t>(bodylen));
    std::memcpy(frame.data() + HDR_BYTES, ctr_be, CTR_BYTES);

    unsigned char *ct  = frame.data() + HDR_BYTES + CTR_BYTES;
    unsigned char *tag = ct + ptlen;

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

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_, nonce) != 1)
            break;

        // Authenticate the counter along with the encrypted data
        if (EVP_EncryptUpdate(ctx, nullptr, &outl,
                              ctr_be, static_cast<int>(CTR_BYTES)) != 1)
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

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(TAG_BYTES), tag) != 1)
            break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
        return false;

    // Increment only after encryption succeeds
    send_ctr_++;

    return net::write_all(fd, frame.data(), frame.size());
}

RecvResult SecureChannel::recv_msg(int fd, std::string &plaintext_out)
{
    if (!ready_)
        return RecvResult::ProtocolError;

    plaintext_out.clear();

    unsigned char hdr[HDR_BYTES];
    if (!net::read_exact(fd, hdr, HDR_BYTES))
        return RecvResult::Closed;

    const uint32_t bodylen = get_u32_be(hdr);

    // Check the received length before allocating memory
    if (bodylen < MIN_BODY_BYTES || bodylen > MAX_BODY_BYTES)
        return RecvResult::ProtocolError;

    std::vector<unsigned char> body(bodylen);
    if (!net::read_exact(fd, body.data(), bodylen))
        return RecvResult::Closed;

    const uint64_t ctr = get_u64_be(body.data());

    // Messages must arrive in the expected order
    if (ctr != recv_ctr_)
        return RecvResult::ProtocolError;

    const size_t ctlen = bodylen - CTR_BYTES - TAG_BYTES;

    const unsigned char *ct  = body.data() + CTR_BYTES;
    const unsigned char *tag = ct + ctlen;

    unsigned char nonce[NONCE_BYTES];
    build_nonce(nonce, recv_dir_, ctr);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return RecvResult::ProtocolError;

    // Keep the buffer valid even for an empty message
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

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_, nonce) != 1)
            break;

        // Authenticate the counter the same way as the sender
        if (EVP_DecryptUpdate(ctx, nullptr, &outl,
                              body.data(), static_cast<int>(CTR_BYTES)) != 1)
            break;

        if (ctlen > 0) {
            if (EVP_DecryptUpdate(ctx, pt.data(), &outl,
                                  ct, static_cast<int>(ctlen)) != 1)
                break;
        }

        // Set the authentication tag before checking the final result
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                static_cast<int>(TAG_BYTES),
                                const_cast<unsigned char *>(tag)) != 1)
            break;

        int finl = 0;

        // DecryptFinal verifies the authentication tag
        if (EVP_DecryptFinal_ex(ctx, pt.data() + ctlen, &finl) <= 0)
            break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        OPENSSL_cleanse(pt.data(), pt.size());
        return RecvResult::AuthFailure;
    }

    // Move to the next expected message counter
    recv_ctr_++;

    plaintext_out.assign(reinterpret_cast<const char *>(pt.data()), ctlen);
    OPENSSL_cleanse(pt.data(), pt.size());

    return RecvResult::Ok;
}

}  // namespace crypto