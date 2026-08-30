# CS6008 Phase 2 — Client–Server Confidentiality via Diffie–Hellman

A two-client TCP chat application in which each client performs its own
Diffie–Hellman key exchange with the server, and every application message is
protected with AES-256-GCM authenticated encryption.

## Files

| File | Purpose |
|---|---|
| `dh.h` / `dh.cpp` | RFC 3526 group 14 parameters, our own `my_mod_exp`, key pair generation, peer-value validation, the socket handshake |
| `crypto.h` / `crypto.cpp` | SHA-256 key derivation, key fingerprint, AES-256-GCM record layer |
| `net.h` / `net.cpp` | `read_exact` / `write_all` — partial-read and partial-write safe |
| `server.cpp` | Chat server; one independent DH exchange and key per client |
| `client.cpp` | Chat client; `@user`, `/chat`, `/who`, `/quit` |
| `dh_test.cpp` | Test harness for `dh.cpp`. **The only file that references OpenSSL's own modexp**, used purely as a cross-check |
| `tamper_proxy.cpp` | Flips one bit of one record's ciphertext, for the §3.2 tamper-detection test |

## Build

```bash
sudo apt update
sudo apt install -y g++ make libssl-dev
make
```

Produces `server`, `client`, `dh_test`, `tamper_proxy`.

Explicit commands, if you prefer not to use `make`:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pthread server.cpp dh.cpp crypto.cpp net.cpp -o server       -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread client.cpp dh.cpp crypto.cpp net.cpp -o client       -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread dh_test.cpp dh.cpp net.cpp        -o dh_test      -lcrypto
g++ -std=c++17 -O2 -Wall -Wextra -pthread tamper_proxy.cpp net.cpp          -o tamper_proxy -lcrypto
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

- no `<openssl/dh.h>`, DH/ECDH API, `EVP_PKEY_derive` or TLS/SSL call appears
  in any source file;
- `BN_mod_exp` appears in `dh_test.cpp` only;
- the linked `server` and `client` binaries do not import `BN_mod_exp` at all
  (checked with `nm -uC`).

## Tamper-detection test (§3.2)

On the client VM:

```bash
./tamper_proxy 6000 <server-ip> 5000 s2c 2      # corrupt the 2nd server->client frame
./client 127.0.0.1 6000
```

Register, then type `/who`. The proxy reports the bit it flipped and the
client reports an AES-GCM authentication failure and aborts without
displaying any plaintext.

Frame 0 in each direction is the DH public value; encrypted records start at
frame 1. Use `c2s` instead of `s2c` to corrupt a client-to-server record and
see the server reject it.

## Security notes

- The raw DH shared secret is never used as a key. The key is
  `SHA-256("CS6008-P2-KEY-v1" || Z)`, where `Z` is the secret serialised to a
  fixed 256 bytes.
- The printed fingerprint is `SHA-256("CS6008-P2-FP-v1" || key)` truncated to
  8 bytes. The differing label means it reveals neither the key nor `Z`.
- Private exponents, raw shared secrets and derived keys are never printed and
  are wiped with `OPENSSL_cleanse` as soon as they are no longer needed.
- Nonces are `[4-byte direction tag][8-byte counter]`. The two directions use
  different tags, so one key is safe for both. Counters never wrap.
- `my_mod_exp` branches on the exponent bit, so its running time correlates
  with the Hamming weight of the private exponent. Documented limitation; a
  Montgomery ladder is the fix.
