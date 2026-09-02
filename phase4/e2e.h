/*
 * e2e.h -- CS6008 Phase 4: end-to-end encryption primitives (Checkpoint 1)
 *
 * WHY A SEPARATE MODULE. crypto::SecureChannel is socket-bound: send_msg /
 * recv_msg take an fd, do their own length framing via net::write_all /
 * read_exact, and carry per-connection monotonic counters used to build GCM
 * nonces. That is exactly right for the outer client-server link and exactly
 * wrong for the inner E2E layer, where the ciphertext is a *string* that
 * travels inside the existing "MSG|recipient|payload" relay and never touches
 * a socket directly. Forcing SecureChannel to do both would entangle the two
 * counter spaces. So the inner layer gets its own small, in-memory AEAD here,
 * and crypto.cpp is left completely untouched.
 *
 * Allowed-tools note (assignment §1.2): only low-level OpenSSL primitives are
 * used -- <openssl/evp.h> for AES-256-GCM and <openssl/rand.h> for the nonce.
 * No TLS/SSL, no <openssl/dh.h>, no DH/ECDH or EVP_PKEY key-agreement API.
 * The DH itself is NOT here: Checkpoint 2 will reuse the project's existing
 * dh::KeyPair unchanged.
 *
 * Checkpoint 1 scope: Base64 + in-memory AEAD only. No session state, no
 * INIT/ACK, no message wrapping, no /e2e command, no key rotation.
 */

#ifndef E2E_H
#define E2E_H

#include <cstddef>
#include <string>
#include <vector>

namespace e2e {

/* ---------------------------------------------------------------- */
/* sizes                                                             */
/* ---------------------------------------------------------------- */

constexpr size_t KEY_BYTES   = 32;   /* AES-256, matches crypto::KEY_BYTES */
constexpr size_t NONCE_BYTES = 12;   /* 96-bit GCM nonce (native size)     */
constexpr size_t TAG_BYTES   = 16;   /* GCM tag                            */

/*
 * Maximum inner plaintext, in bytes.
 *
 * The wrapped message travels as  MSG|<user>|__E2E_MSG__<base64>  inside the
 * outer record, whose plaintext cap is crypto::MAX_PLAINTEXT = 4096. Base64
 * expands by 4/3, so 2048 bytes of plaintext becomes
 *   ceil((12 + 2048 + 16) / 3) * 4 = 2768 base64 chars,
 * leaving ~1300 bytes of headroom for "MSG|", the username, and the tag.
 * A deliberately conservative cap: it cannot overflow the outer limit.
 */
constexpr size_t MAX_E2E_PLAINTEXT = 2048;

/* ---------------------------------------------------------------- */
/* Base64                                                            */
/* ---------------------------------------------------------------- */

/*
 * Standard Base64 with '=' padding. The alphabet is [A-Za-z0-9+/=], which
 * contains no '|', no space and no newline -- so an encoded payload can never
 * collide with the "MSG|recipient|message" split performed by the server, nor
 * with the outer record framing.
 */
std::string base64_encode(const unsigned char *data, size_t len);

/*
 * Strict decoder. Returns false on any malformed input: illegal character,
 * length not a multiple of 4, or misplaced padding. Being strict matters --
 * this parses attacker-reachable data arriving from the relay.
 */
bool base64_decode(const std::string &text, std::vector<unsigned char> &out);

/* ---------------------------------------------------------------- */
/* in-memory authenticated encryption                                */
/* ---------------------------------------------------------------- */

/*
 * seal: plaintext -> base64( nonce || ciphertext || tag )
 *
 * A fresh 12-byte nonce is drawn from the CSPRNG (RAND_bytes) for EVERY
 * call, so a (key, nonce) pair is never reused even across rekeys. The nonce
 * is prepended in the clear -- it is not secret, and the receiver needs it.
 *
 * Returns false if plaintext exceeds MAX_E2E_PLAINTEXT, if the RNG fails, or
 * if the cipher fails. On failure out is left untouched.
 */
bool seal(const unsigned char key[KEY_BYTES],
          const std::string &plaintext,
          std::string &out_b64);

/*
 * open: base64( nonce || ciphertext || tag ) -> plaintext
 *
 * Returns false if the Base64 is malformed, if the blob is too short to
 * contain a nonce and a tag, if it exceeds the size cap, or if the GCM tag
 * does not verify. A tag failure means the payload was altered, truncated or
 * forged: NO plaintext is produced and the caller must discard the message.
 */
bool open(const unsigned char key[KEY_BYTES],
          const std::string &in_b64,
          std::string &out_plaintext);

/* ================================================================ */
/* Checkpoint 2: client-to-client DH session establishment          */
/* ================================================================ */

/*
 * Wire tags, exactly as mandated by the assignment (§1.4). These are the
 * literal prefixes carried inside the ordinary "MSG|recipient|payload" relay
 * body, so the server forwards them opaquely and needs no change.
 */
extern const char TAG_INIT[];   /* "__E2E_INIT__" */
extern const char TAG_ACK[];    /* "__E2E_ACK__"  */
extern const char TAG_MSG[];    /* "__E2E_MSG__"  */

/*
 * KDF domain separation.
 *
 * IMPORTANT AND ACCURATE: crypto::derive_key(shared, len, out) does NOT take
 * a label parameter -- its Phase 2 context "CS6008-P2-KEY-v1" is a file-local
 * constant inside crypto.cpp and is not caller-supplied. crypto.cpp/.h are
 * left completely unchanged.
 *
 * Domain separation is therefore achieved by PREFIXING THE KDF INPUT: we hand
 * crypto::derive_key the buffer ("CS6008-P4-E2E-v1" || Z) instead of Z alone,
 * so the E2E key is SHA-256("CS6008-P2-KEY-v1" || "CS6008-P4-E2E-v1" || Z),
 * which is unrelated to the outer link key SHA-256("CS6008-P2-KEY-v1" || Z)
 * derived from a different exchange.
 */
extern const char E2E_KDF_CONTEXT[];   /* "CS6008-P4-E2E-v1" */

/*
 * HANDSHAKE BINDING (fixes the stale/delayed-ACK divergence).
 *
 * An ACK must be provably the answer to the INIT we currently have pending,
 * not to some earlier superseded one. Without this, a delayed but
 * cryptographically valid ACK(B1) from handshake H1, arriving after a
 * replacement handshake H2 was started, would be combined with H2's private
 * key A2 to yield DH(A2,B1) -- a key the peer never derives. Both sides then
 * report "established" with different keys.
 *
 * Binding mechanism (deliberately the smallest thing that works): the
 * responder echoes the first BIND_BYTES bytes of SHA-256(initiator_public)
 * at the front of the ACK payload. The initiator recomputes the same digest
 * from its own pending public value and rejects any mismatch.
 *
 *   __E2E_INIT__ base64( A )                        -- 256 bytes
 *   __E2E_ACK__  base64( bind(8) || B )             -- 8 + 256 bytes
 *
 * It needs no extra stored state (the initiator already holds A), no extra
 * round trip, stays opaque to the server, and works unchanged for Phase 5
 * rekeying because every rotation uses a fresh A. The 8 bytes are a
 * same-session correlator, not a security boundary: DH validation and the
 * GCM tag remain the actual protections.
 */
constexpr size_t BIND_BYTES = 8;

/*
 * Per-peer session state, derived from two INDEPENDENT internal facts:
 *   - does a usable key exist?          (survives a pending re-handshake)
 *   - is a handshake currently pending? (a local keypair awaiting an ACK)
 *
 * They are independent because a replacement handshake must NOT make an
 * already-working session unusable while it is in flight:
 *
 *   usable key | pending | state_of() returns | get_key() succeeds
 *   -----------+---------+--------------------+-------------------
 *      no      |   no    | None               | no
 *      no      |  yes    | InitSent           | no
 *     yes      |   no    | Established        | YES
 *     yes      |  yes    | Established        | YES  <-- old key still usable
 *
 * Use has_pending() to ask specifically whether a handshake is in flight.
 * Phase 5's rotation reuses exactly this property.
 */
enum class State {
    None,           /* no usable key, nothing pending        */
    InitSent,       /* no usable key yet, awaiting peer's ACK */
    Established     /* a usable key exists                   */
};

/* Result of a manager operation. Distinct codes so callers (and tests) can
   tell a protocol rejection from a crypto failure. */
enum class Result {
    Ok,
    BadState,       /* operation not legal in the current state    */
    BadFormat,      /* missing tag, bad Base64, wrong length       */
    DhFailure,      /* peer public value rejected, or DH failed    */
    Internal,       /* keygen/serialisation/derivation failure     */
    GlareIgnored    /* simultaneous INIT: we won the tie-break, so */
                    /* the peer's INIT is deliberately ignored and */
                    /* NO ack should be sent (see glare rule)      */
};

const char *result_str(Result r);

/*
 * E2EManager owns all per-peer sessions and all locking.
 *
 * Deliberate API shape: every method performs a COMPLETE operation under the
 * lock (validate state -> act -> transition -> return a value). No method
 * hands out a pointer or reference to internal session state, so a caller can
 * never touch a session after the lock is released. This is what makes it
 * safe for the client's input thread and receive thread to share one manager
 * in Checkpoint 3.
 */
/*
 * GLARE RULE (simultaneous INIT).
 *
 * If both peers run /e2e at the same moment, each has a pending INIT when the
 * other's INIT arrives. Without a rule, each would answer the other and the
 * two sides would end up Established with DIFFERENT keys while both believed
 * the handshake had succeeded.
 *
 * Deterministic tie-break: THE LEXICOGRAPHICALLY LOWER USERNAME WINS the
 * initiator role. Both sides compute this from the same two names, with no
 * extra messages, so they always reach the same decision:
 *
 *   - Winner  (self < peer): keeps its own pending handshake and IGNORES the
 *     peer's INIT, returning Result::GlareIgnored (send no ACK). It then
 *     completes normally when the loser's ACK arrives.
 *   - Loser   (self > peer): abandons its own pending handshake and processes
 *     the peer's INIT normally, deriving the key and replying with an ACK.
 *     Its own earlier INIT is answered by nobody; the later stray ACK, if any,
 *     is rejected without touching the established key.
 *
 * Exactly one handshake therefore survives, and both sides derive the same
 * key from that single exchange. Usernames are distinct because the server
 * rejects duplicate registrations, so the comparison is never a tie.
 */
class E2EManager {
public:
    /* self_username is this client's own registered name; it is required to
       evaluate the glare rule above. */
    explicit E2EManager(const std::string &self_username);
    ~E2EManager();

    E2EManager(const E2EManager &) = delete;
    E2EManager &operator=(const E2EManager &) = delete;

    /*
     * Initiator. Generates a fresh DH keypair for `peer`, stores it as the
     * pending handshake, and returns "__E2E_INIT__<base64(A)>" in out_msg.
     *
     * FAILURE CONTRACT: if key generation or serialisation fails, NOTHING is
     * modified -- no pending handshake is installed and any existing session
     * and key for that peer remain exactly as they were. A failed start()
     * can never damage a working session.
     *
     * If a usable key already exists, it REMAINS usable (get_key() keeps
     * succeeding) while this replacement handshake is in flight.
     */
    Result start(const std::string &peer, std::string &out_msg);

    /*
     * Responder. Consumes "__E2E_INIT__<base64(A)>", generates a fresh
     * keypair, computes Z via the project's existing dh::KeyPair, derives the
     * E2E key, and returns "__E2E_ACK__<base64(bind(8) || B)>" in out_msg,
     * where bind = SHA-256(A)[0..7] ties the ACK to the INIT being answered.
     *
     * The complete ACK is built BEFORE the session is committed, so an
     * internal failure during preparation leaves the existing key and pending
     * state untouched.
     *
     * The session is established ONLY after key derivation succeeds. If the
     * peer's public value fails dh validation, any pre-existing session and
     * any pending handshake are left untouched.
     *
     * Returns Result::GlareIgnored when the glare rule says we won the
     * tie-break; the caller must then send NO ack and simply wait for the
     * peer's ack to our own INIT.
     */
    Result handle_init(const std::string &peer, const std::string &wire,
                       std::string &out_msg);

    /*
     * Initiator completing the handshake. Consumes
     * "__E2E_ACK__<base64(bind(8) || B)>". The bind field must match a digest
     * of OUR currently pending public value, so an ACK belonging to an older
     * handshake is rejected without consuming the live pending handshake or
     * altering the working key. Requires a pending handshake for that peer; an
     * ACK arriving with no pending INIT is rejected (BadState) and cannot
     * alter an existing key.
     */
    Result handle_ack(const std::string &peer, const std::string &wire);

    /* Introspection for the client UI and for tests. */
    State state_of(const std::string &peer);

    /* True when a USABLE key exists -- including while a replacement
       handshake is pending. */
    bool  is_established(const std::string &peer);

    /* True when a local keypair is awaiting the peer's ACK. Independent of
       is_established(): both can be true during a replacement. */
    bool  has_pending(const std::string &peer);

    /*
     * Copy the established key for `peer` into key_out. Returns false if the
     * peer is not established. Copying (rather than exposing a pointer) keeps
     * the lock discipline intact.
     */
    bool get_key(const std::string &peer, unsigned char key_out[KEY_BYTES]);

    /* Fingerprint of the established key, via crypto::fingerprint. Returns
       an empty string if the peer is not established. The fingerprint is
       computed locally and is never transmitted. */
    std::string fingerprint_of(const std::string &peer);

    /* Forget a peer's session, wiping key material. */
    void clear(const std::string &peer);

private:
    struct Impl;
    Impl *impl_;
};

}  /* namespace e2e */

#endif /* E2E_H */
