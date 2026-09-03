/*
 * crypto.cpp
 */

#include "crypto.h"
#include "net.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <arpa/inet.h>

#include <cstring>
#include <vector>

namespace crypto {

// small helpers

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

// nonce = [4-byte direction tag][8-byte counter]
static void build_nonce(unsigned char nonce[NONCE_BYTES],
                        uint32_t dir, uint64_t ctr)
{
    put_u32_be(nonce, dir);
    put_u64_be(nonce + 4, ctr);
}

// key derivation and fingerprint

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

    // sizeof(LABEL) - 1 drops the terminating NUL so the label is a fixed
    // 16 bytes on both sides
    if (!sha256_two(KEY_LABEL, sizeof(KEY_LABEL) - 1,
                    shared, shared_len, digest)) {
        // a digest failure means something is badly wrong with OpenSSL --
        // return a zero key instead of pretending we derived a real one
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

    // first 8 bytes, grouped in fours so it's easy to read/screenshot
    for (int i = 0; i < 8; i++) {
        if (i > 0 && i % 2 == 0)
            out += ' ';
        out += hexdigits[digest[i] >> 4];
        out += hexdigits[digest[i] & 0x0F];
    }

    OPENSSL_cleanse(digest, sizeof(digest));
    return out;
}

// SecureChannel

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

    // distinct direction tags so both directions can share one key
    // without ever sharing a nonce
    if (role == Role::Client) {
        send_dir_ = 1;      /* client -> server */
        recv_dir_ = 2;      /* server -> client */
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

    // 2^64 records won't happen in practice, but wrapping the counter
    // would mean reusing a nonce, so just refuse instead
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

        // the counter goes over the wire in clear text, so bind it as AAD --
        // altering it in flight breaks the tag
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
                break;      // GCM is a stream mode: ciphertext length == plaintext length
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

    send_ctr_++;    /* only after a successful encryption */

    return net::write_all(fd, frame.data(), frame.size());
}

RecvResult SecureChannel::recv_msg(int fd, std::string &plaintext_out)
{
    if (!ready_)
        return RecvResult::ProtocolError;

    plaintext_out.clear();

    // length, validated before we allocate anything

    unsigned char hdr[HDR_BYTES];
    if (!net::read_exact(fd, hdr, HDR_BYTES))
        return RecvResult::Closed;

    const uint32_t bodylen = get_u32_be(hdr);

    if (bodylen < MIN_BODY_BYTES || bodylen > MAX_BODY_BYTES)
        return RecvResult::ProtocolError;

    std::vector<unsigned char> body(bodylen);
    if (!net::read_exact(fd, body.data(), bodylen))
        return RecvResult::Closed;

    // counter must match exactly what we expect next

    const uint64_t ctr = get_u64_be(body.data());

    // strict sequencing -- a replayed, reordered or dropped record gets
    // rejected right here instead of being decrypted, which also means a
    // replay can never reuse a nonce against us
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

    // ctlen + 1 so the buffer is never empty -- pt.data() has to stay a
    // valid pointer even for a zero-length message
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

        if (EVP_DecryptUpdate(ctx, nullptr, &outl,
                              body.data(), static_cast<int>(CTR_BYTES)) != 1)
            break;      // counter as AAD, same as the sender bound it

        if (ctlen > 0) {
            if (EVP_DecryptUpdate(ctx, pt.data(), &outl,
                                  ct, static_cast<int>(ctlen)) != 1)
                break;
        }

        // the tag has to be installed before DecryptFinal
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                static_cast<int>(TAG_BYTES),
                                const_cast<unsigned char *>(tag)) != 1)
            break;

        int finl = 0;

        // this is the actual authentication check -- a non-positive return
        // means the tag didn't verify (altered, replayed or forged), and no
        // plaintext comes out of this
        if (EVP_DecryptFinal_ex(ctx, pt.data() + ctlen, &finl) <= 0)
            break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        OPENSSL_cleanse(pt.data(), pt.size());
        return RecvResult::AuthFailure;
    }

    recv_ctr_++;    // only bump this once the tag has actually verified

    plaintext_out.assign(reinterpret_cast<const char *>(pt.data()), ctlen);
    OPENSSL_cleanse(pt.data(), pt.size());

    return RecvResult::Ok;
}

}  /* namespace crypto */
