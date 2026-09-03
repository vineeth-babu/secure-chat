# CS6008 Phase 2 — Client–Server Confidentiality via Diffie–Hellman

A two-client TCP chat application in which each client performs its own
Diffie–Hellman key exchange with the server, and every application message is
protected with AES-256-GCM authenticated encryption. The phase also includes
the two attacker tools the assignment requires: a tamper test (§3.2) and an
active man-in-the-middle proxy (§3.3).

## Diffie–Hellman: what we implement vs. what OpenSSL provides

The DH *protocol* is implemented in `dh.cpp`, in application code that
explicitly controls every step: private-exponent generation, public-value
computation `A = g^a mod p`, exchange of public values, peer-value validation,
and shared-secret computation `Z = B^a mod p`.

The modular exponentiation inside those steps is evaluated with OpenSSL's
generic big-integer primitive `BN_mod_exp` (`base^exp mod m`). Per the course
TA's clarification, this generic primitive is the intended building block: a
function is disallowed only if it performs the DH exchange itself (e.g.
`DH_generate_key`, `DH_compute_key`, or `EVP_PKEY_derive` used for DH). We use
none of those. `BN_mod_exp` has no notion of a group, a key, or a peer — the
protocol around it is ours.

Every exponentiation in the module funnels through one wrapper, `my_mod_exp`
in `dh.cpp`, which calls `BN_mod_exp` with the constant-time flag
(`BN_FLG_CONSTTIME`) set, so the primitive is chosen in exactly one place and
runs on a timing-independent path.

## Files

| File | Purpose |
|---|---|
| `dh.h` / `dh.cpp` | RFC 3526 group 14 parameters, `my_mod_exp` (wrapper over `BN_mod_exp`), key-pair generation, peer-value validation, the socket handshake |
| `crypto.h` / `crypto.cpp` | SHA-256 key derivation, key fingerprint, AES-256-GCM record layer |
| `net.h` / `net.cpp` | `read_exact` / `write_all` — partial-read and partial-write safe |
| `server.cpp` | Chat server; one independent DH exchange and key per client |
| `client.cpp` | Chat client; `@user`, `/chat`, `/who`, `/quit` |
| `dh_test.cpp` | Test harness for `dh.cpp`: toy vectors, group-14 primality, a full exchange, hostile-value rejection, and an algebraic self-consistency check |
| `tamper_proxy.cpp` | Flips one bit of one record's ciphertext, for the §3.2 tamper-detection test |
| `mitm_proxy.cpp` | Active man-in-the-middle: two independent DH exchanges, decrypts and re-encrypts in the clear, for the §3.3 attack task |

## Build

```bash
sudo apt update
sudo apt install -y g++ make libssl-dev
make
```

Produces `server`, `client`, `dh_test`, `tamper_proxy`, `mitm_proxy`.

Explicit commands, if you prefer not to use `make`:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pthread server.cpp       dh.cpp crypto.cpp net.cpp -o server       -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread client.cpp       dh.cpp crypto.cpp net.cpp -o client       -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread dh_test.cpp      dh.cpp net.cpp            -o dh_test      -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread tamper_proxy.cpp net.cpp                   -o tamper_proxy -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread mitm_proxy.cpp   dh.cpp crypto.cpp net.cpp -o mitm_proxy   -lcrypto
```

## Run

Server VM:

```bash
./server
```

Client VMs:

```bash
./client <server-ip> [port]      # e.g. ./client 192.168.64.2 5000
```

The server listens on `0.0.0.0:5000`, so it is reachable from the other VMs.

## Commands (assignment §1.3)

| Command | Behaviour |
|---|---|
| `@username message` | send to `username` and select them as the current partner |
| `/chat username` | select `username` without sending |
| `/who` | list online users |
| `/quit` | disconnect cleanly and exit |
| anything else | sent as a chat message to the currently selected partner |

## Verification

```bash
make check
```

This runs the DH test harness and then proves, mechanically, that:

- no OpenSSL DH/ECDH exchange API (`DH_*`, `ECDH_*`, `EVP_PKEY_derive`) and no
  TLS/SSL header or call appears in any source file;
- the files that call `BN_mod_exp` are exactly the DH module (`dh.cpp`), its
  test harness (`dh_test.cpp`), and the MITM proxy (`mitm_proxy.cpp`) — each
  using it only as the generic `base^exp mod m` primitive.

## Tamper-detection test (§3.2)

On the client VM (or on the Mallory VM):

```bash
./tamper_proxy 6000 <server-ip> 5000 s2c 2      # corrupt a server->client record
./client 127.0.0.1 6000
```

Register, then send a message or type `/who` so a record flows in the chosen
direction. The proxy reports the bit it flipped, and the receiving side
reports an AES-GCM authentication failure and aborts without displaying any
plaintext.

Frame 0 in each direction is the DH public value; encrypted records start at
frame 1. The `OK|Registered` reply is the first server→client record, so
corrupting an early `s2c` frame surfaces as a failure during registration;
corrupting a later one surfaces mid-chat. Use `c2s` instead of `s2c` to
corrupt a client-to-server record and see the server reject it.

## Man-in-the-middle attack (§3.3)

Run the proxy on the Mallory VM and point the victim client at it manually:

```bash
# Mallory VM
./mitm_proxy 7000 <server-ip> 5000

# Victim client VM — aim at Mallory, not the server
./client <mallory-ip> 7000
```

The proxy performs two independent DH exchanges — one with the victim (playing
the server), one with the real server (playing the client) — and relays every
message, printing the application plaintext it intercepts. The victim's key
fingerprint matches Mallory's victim-side key; the server records a *different*
fingerprint (its key with Mallory). In a genuine session those two would be
equal. Neither endpoint sees the other's fingerprint, so neither can detect the
attack — which is exactly why Phase 3 adds an authenticated server certificate.

## Security notes

- The raw DH shared secret is never used as a key. The key is
  `SHA-256("CS6008-P2-KEY-v1" || Z)`, where `Z` is the secret serialised to a
  fixed 256 bytes with `BN_bn2binpad`.
- The printed fingerprint is `SHA-256("CS6008-P2-FP-v1" || key)` truncated to
  8 bytes. The differing label means it reveals neither the key nor `Z`.
- Private exponents, raw shared secrets and derived keys are never printed and
  are wiped with `OPENSSL_cleanse` as soon as they are no longer needed.
- Nonces are `[4-byte direction tag][8-byte counter]`. The two directions use
  different tags, so one key is safe for both. Counters never wrap.
- `my_mod_exp` sets `BN_FLG_CONSTTIME`, so `BN_mod_exp` runs its constant-time
  path and the exponentiation does not leak the private exponent through
  timing.
