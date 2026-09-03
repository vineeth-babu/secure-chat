# Phase 3 - Server Authentication via PKI

Phase 3 adds certificate-based server authentication and proof of private
key possession, running before the Diffie-Hellman exchange from Phase 2. The
active MITM that worked against plain DH is now caught and rejected before
any DH byte goes out. Nothing from Phase 2 changed - the custom DH, the
AES-256-GCM chat, and tamper detection all still work exactly the same.

## What's new compared to Phase 2

New files:

| File | What it does |
|---|---|
| `certs.h` / `certs.cpp` | Loads X.509 certs, validates them, signs/verifies the challenge. Only uses `x509.h`, `evp.h`, `pem.h`, `rand.h` - no TLS, no DH/ECDH API |
| `gen_certs.sh` | Generates the CA, server key, and a CA-signed server cert with an IP SAN |
| `mitm_proxy_p3.cpp` | Same two-socket MITM as before, but now defeated - either at certificate validation (`fake` mode) or at proof-of-possession (`copied` mode) |

Changed: `client.cpp` (validates the server before doing DH), `server.cpp`
(loads its cert+key at startup, proves possession before DH), `Makefile`.

Untouched: `dh.*`, `crypto.*`, `net.*`, `tamper_proxy.cpp`, `mitm_proxy.cpp`,
`dh_test.cpp`.

## The handshake (new steps in bold)

```
Client                                         Server
  |-------------- TCP connect ----------------->|
  | **receive server certificate (DER)** <------| **send certificate**
  | **validate: CA chain, validity, IP SAN**    |
  |   fail -> abort, send nothing, close        |
  | **send 32-byte random challenge** --------->| **read challenge**
  | **receive signature** <---------------------| **sign challenge (SHA-256)**
  | **verify signature vs cert public key**     |
  |   fail -> abort, close                       |
  |========= existing DH exchange ==============|  (unchanged)
  |========= existing AES-256-GCM chat =========|  (unchanged)
```

The client sends no challenge, no username, and no DH value until the
certificate and the signature have both passed.

## Build

```bash
sudo apt install -y g++ make libssl-dev
make
```

## Generating the PKI

Run this on the server machine. Pass the IP the clients will actually dial,
since that's what goes into the cert's SAN:

```bash
make certs IP=192.168.64.2      # or: ./gen_certs.sh 192.168.64.2
```

This makes `ca-cert.pem` (copy this to clients), `server-cert.pem` +
`server-key.pem` (server only), and `ca-key.pem` (keep this offline). For
testing on one machine just use `127.0.0.1`.

## Running

```bash
# server (looks for ./server-cert.pem and ./server-key.pem by default)
./server

# client:  ./client <connect-ip> <port> <ca-cert> [expected-server-ip]
./client 192.168.64.2 5000 ca-cert.pem

# through a proxy: TCP goes to the proxy, but we still authenticate the
# real server's identity
#   ./client <proxy-ip> <proxy-port> <ca-cert> <real-server-ip>
./client 192.168.64.10 5001 ca-cert.pem 192.168.64.2
```

The client checks the server's cert against `ca-cert.pem` and verifies the
signature over its challenge before doing anything else.

## Certificate identity (IP SAN)

Since the server is reached by IP, the cert carries the server's IP as an IP
SAN, and the client checks it with `X509_check_ip_asc`. A cert that's signed
correctly but has the wrong IP still gets rejected - CN isn't used for the
actual security decision here.

## Attack demos

`mitm_proxy_p3` is the same two-socket setup as `mitm_proxy.cpp`: Mallory
listens for the victim and also opens a real connection to the genuine
server. What's different is that the victim now runs the cert/challenge
check first, and that's what stops the attack.

Point the victim at the proxy: `./client 127.0.0.1 7000 ca-cert.pem`.

**Fake certificate** - Mallory presents a self-signed cert:

```bash
./mitm_proxy_p3 7000 <server-ip> 5000 fake rogue-cert.pem rogue-key.pem
```

The victim rejects it at validation and never sends a challenge - Mallory
never even reaches DH.

**Copied certificate, no private key** - Mallory presents the real cert:

```bash
# on Mallory: forward to the real server, present the copied cert
./mitm_proxy_p3 5001 192.168.64.2 5000 copied server-cert.pem

# Alice: connect to Mallory over TCP, but authenticate the REAL server's
# identity (4th arg). Without it, validation fails on the proxy's own
# address before we'd ever get to test proof-of-possession.
./client 192.168.64.10 5001 ca-cert.pem 192.168.64.2
```

Validation passes here (it really is the genuine cert, and 192.168.64.2 is
in its SAN), the victim sends a challenge, and Mallory can't sign it. This is
the point of the demo: a copied cert clears CA/validity/identity checks just
fine, but the attack still fails because Mallory doesn't have the private
key.

Worth noting: the server only signs the challenge, not the DH values. So a
Mallory that *forwards* the victim's challenge to the real server and relays
back the real signature would actually pass this check. This driver
deliberately only shows the non-forwarding attempt, and prints a note about
binding the signature to `client_pub || server_pub` as the fix for that gap.

## Proof-of-possession details

- Challenge: 32 fresh random bytes from `RAND_bytes`, generated fresh per
  connection.
- What gets signed: just the 32-byte challenge, via `EVP_DigestSign`
  (SHA-256) with the server's RSA-2048 key, verified with
  `EVP_DigestVerify` against the cert's public key.
- Replay resistance: the challenge is fresh every time, so an old captured
  signature won't verify against a new one. Someone with only the public
  cert has no way to sign the new challenge.
- Known limitation: since the signature only covers the challenge (not the
  DH public values), it doesn't rule out a MITM that already holds a valid
  cert of its own - that's outside this threat model anyway, since here the
  attacker has no valid cert. Binding `client_pub || server_pub` into the
  signed data would close that gap too.
