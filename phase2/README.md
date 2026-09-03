# CS6008 Phase 2 — Confidential Client–Server Chat

Phase 2 adds confidentiality and message authentication to the Phase 1 chat application. Each client performs a Diffie–Hellman key exchange with the server, and the application messages are then protected using AES-256-GCM.

This phase also includes programs for testing message tampering and a man-in-the-middle attack.

## Diffie–Hellman implementation

The Diffie–Hellman protocol is implemented in `dh.cpp`. The program handles private exponent generation, public value generation, exchange of public values, validation of the received public value, and shared secret calculation.

OpenSSL is used for its big-number operations and random number generation. The modular exponentiation operation is performed using `BN_mod_exp`.

The raw shared secret is not directly used as the AES key. It is first processed using SHA-256 to derive a 256-bit key.

## Files

| File                      | Purpose                                                            |
| ------------------------- | ------------------------------------------------------------------ |
| `dh.h` / `dh.cpp`         | Diffie–Hellman implementation using RFC 3526 Group 14              |
| `crypto.h` / `crypto.cpp` | Key derivation, fingerprint generation, and AES-256-GCM encryption |
| `net.h` / `net.cpp`       | Socket functions for reliable reads and writes                     |
| `server.cpp`              | Chat server with a separate DH exchange for each client            |
| `client.cpp`              | Chat client supporting messaging and user selection                |
| `dh_test.cpp`             | Tests the Diffie–Hellman implementation                            |
| `tamper_proxy.cpp`        | Modifies an encrypted record to test tamper detection              |
| `mitm_proxy.cpp`          | Demonstrates a man-in-the-middle attack                            |

## Build

Install the required packages:

```bash
sudo apt update
sudo apt install -y g++ make libssl-dev
```

Build all programs:

```bash
make
```

This creates:

```text
server
client
dh_test
tamper_proxy
mitm_proxy
```

The programs can also be compiled individually using the commands in the `Makefile`.

## Run

Start the server:

```bash
./server
```

Start a client:

```bash
./client <server-ip> [port]
```

For example:

```bash
./client 192.168.64.2 5000
```

The default server port is `5000`.

## Client commands

| Command             | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `@username message` | Sends a message to the user and selects them as the current chat partner |
| `/chat username`    | Selects a chat partner without sending a message                         |
| `/who`              | Shows the currently connected users                                      |
| `/quit`             | Disconnects from the server and exits                                    |
| Any other text      | Sends the text to the currently selected chat partner                    |

## Testing

The following command builds the programs and runs the available checks:

```bash
make check
```

The DH test program checks different parts of the Diffie–Hellman implementation, including key generation, shared secret calculation, public value validation, and invalid input handling.

The `check` target also scans the source files for prohibited DH/ECDH/TLS APIs.

## Tamper detection

The `tamper_proxy` program can modify one encrypted record while it is being forwarded.

On the Mallory VM:

```bash
./tamper_proxy 6000 <server-ip> 5000 s2c 2
```

Then connect the client through the Mallory VM:

```bash
./client <mallory-vm-ip> 6000
```

When the encrypted data is modified, AES-GCM authentication fails. The receiving side detects the failure and does not display the modified message as plaintext.

## Man-in-the-middle demonstration

The `mitm_proxy` program demonstrates how an unauthenticated Diffie–Hellman exchange can be intercepted by an active attacker.

On the Mallory VM:

```bash
./mitm_proxy 7000 <server-ip> 5000
```

Then connect the victim client to the Mallory VM instead of directly to the server:

```bash
./client <mallory-vm-ip> 7000
```

The proxy establishes separate Diffie–Hellman exchanges with the client and the server. It can decrypt and relay messages between them because the client and server have not authenticated each other during the key exchange.

This demonstrates why authentication is required in addition to confidentiality, which is addressed in the later phases.

## Security details

* RFC 3526 Group 14 is used for Diffie–Hellman.
* The DH shared secret is hashed using SHA-256 before being used as an AES key.
* AES-256-GCM provides encryption and authentication.
* A key fingerprint is displayed after the key exchange for verification.
* Private exponents, shared secrets, and derived keys are cleared using `OPENSSL_cleanse` when they are no longer needed.
* Each encrypted record uses a counter-based nonce.
* Different directions use different nonce prefixes to avoid nonce reuse.
