# CS6008 Phase 3 — Server Authentication via PKI

Phase 3 adds certificate-based server authentication and proof-of-private-key
possession **before** the Phase 2 Diffie-Hellman exchange runs. The Phase 2
active MITM (which succeeded against unauthenticated DH) is now detected and
rejected before any DH byte is sent. All Phase 2 functionality — custom DH,
AES-256-GCM chat, tamper detection — is unchanged.

## What changed from Phase 2

New files:

| File | Purpose |
|---|---|
| `certs.h` / `certs.cpp` | X.509 loading, certificate validation, challenge signing/verifying. Uses only `<openssl/x509.h>`, `<openssl/evp.h>`, `<openssl/pem.h>`, `<openssl/rand.h>` — no TLS/SSL, no DH/ECDH API |
| `gen_certs.sh` | Generates the CA, server key, and CA-signed server cert with an IP SAN |
| `mitm_proxy_p3.cpp` | Phase 3 update of the two-socket MITM: Mallory still connects to the real server, but is defeated at certificate validation (`fake`) or at proof-of-possession (`copied`) |

Modified: `client.cpp` (validate server before DH), `server.cpp` (load
cert+key at startup, prove possession before DH), `Makefile`.

Unchanged: `dh.*`, `crypto.*`, `net.*`, `tamper_proxy.cpp`, `mitm_proxy.cpp`,
`dh_test.cpp`.

## Handshake (new steps in **bold**)

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
  |========= existing Phase 2 DH ===============|  (unchanged)
  |========= existing AES-256-GCM chat =========|  (unchanged)
```

The client sends no challenge, no username, and no DH value until both the
certificate and the signature have passed.

## Build

```bash
sudo apt install -y g++ make libssl-dev
make                       # builds everything
```

## Generate the PKI

Run on the server host. Pass the IP clients will dial (it goes in the SAN):

```bash
make certs IP=192.168.64.2      # or: ./gen_certs.sh 192.168.64.2
```

Produces `ca-cert.pem` (ship to clients), `server-cert.pem` + `server-key.pem`
(server only), and `ca-key.pem` (keep offline). For local testing use
`127.0.0.1`.

## Run

```bash
# server (defaults to ./server-cert.pem ./server-key.pem)
./server

# client:  ./client <connect-ip> <port> <ca-cert> [expected-server-ip]
./client 192.168.64.2 5000 ca-cert.pem

# When connecting through a proxy, authenticate the REAL server's identity
# while the TCP destination is the proxy:
#   ./client <proxy-ip> <proxy-port> <ca-cert> <real-server-ip>
./client 192.168.64.10 5001 ca-cert.pem 192.168.64.2
```

The client validates the server's certificate against `ca-cert.pem` and
verifies the signature over its challenge, then proceeds to the normal chat.

## Certificate identity (IP SAN)

Because the server is reached by IP (§1.2.1), the certificate carries the
server IP as an **IP Subject Alternative Name**, and the client checks it with
`X509_check_ip_asc`. A certificate that is validly CA-signed but carries the
wrong IP is rejected — CN is not used for the security decision.

## Attack demonstrations (§4.2)

`mitm_proxy_p3` is a genuine update of the Phase 2 two-socket MITM: Mallory
listens for the victim **and** opens a real TCP session to the genuine server
(consuming the server's certificate on that link), exactly as in Phase 2. The
Phase 3 authentication step the victim now runs first is what defeats it.

Point the victim at the proxy (`./client 127.0.0.1 7000 ca-cert.pem`).

**Fake certificate** — Mallory presents a self-signed cert:

```bash
./mitm_proxy_p3 7000 <server-ip> 5000 fake rogue-cert.pem rogue-key.pem
```

The victim rejects it at validation ("certificate validation failed") and
sends no challenge. Mallory never reaches DH.

**Copied certificate, no private key** — Mallory presents the real cert:

```bash
# on Mallory (192.168.64.10): forward to the real server, present the copied cert
./mitm_proxy_p3 5001 192.168.64.2 5000 copied server-cert.pem

# Alice: TCP-connect to Mallory, but AUTHENTICATE the real server's identity.
# The 4th argument is the expected IP SAN (the real server), separate from the
# TCP destination (the proxy). Without it, validation would fail early on the
# proxy's address and never reach proof-of-possession.
./client 192.168.64.10 5001 ca-cert.pem 192.168.64.2
```

Validation passes (the cert is genuine and 192.168.64.2 is in its IP SAN), the
victim sends a challenge, Mallory cannot sign it, and proof-of-possession fails
("signature did not verify"). This is the intended demonstration: a copied
genuine certificate clears CA, validity, and real-server-identity checks, yet
the MITM still fails because it lacks the server's private key.

Because the signature covers only the challenge (not the DH public values), a
copied-cert Mallory that *forwarded the victim's challenge to the real server*
and relayed the real signature back would pass this check. This driver
demonstrates the non-forwarding attempt, which fails, and prints a note
pointing at `challenge || client_pub || server_pub` binding as the fix — the
natural Phase 3 hardening and Phase 4 groundwork.

## Proof-of-possession details

- Challenge: 32 fresh random bytes from `RAND_bytes` per connection.
- Signed bytes: the 32-byte challenge, using `EVP_DigestSign` (SHA-256) with
  the server's RSA-2048 key; verified with `EVP_DigestVerify` against the
  certificate's public key.
- Replay resistance: the challenge is fresh each connection, so a signature
  captured earlier verifies against a different challenge and fails. An
  attacker with only the public certificate has no way to sign the new
  challenge.
- Scope note: the signature covers the challenge only, proving liveness and
  key possession. It does not cryptographically bind the identity to the DH
  public values, so it does not exclude a MITM who is *itself* a valid cert
  holder — not part of this threat model, where the attacker has no valid
  cert. Binding `challenge || client_pub || server_pub` would close that and
  is a natural extension.

## Constraint check

| Requirement | Status |
|---|---|
| Cert exchange before ANY DH | Yes — auth block precedes `dh::run_handshake` on both sides |
| No TLS/SSL, no `<openssl/ssl.h>` | Yes — `make check` scans for and finds none |
| No OpenSSL DH/ECDH exchange API | Yes — signing uses `EVP_DigestSign`/`Verify`, not key agreement |
| Existing custom DH unchanged | Yes — `dh.*` untouched |
| AES-GCM chat intact after auth | Yes — `crypto.*` untouched; verified by two-client regression |
