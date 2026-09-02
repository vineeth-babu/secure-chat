# Phase 5 - Forward Secrecy

This phase extends the Phase 4 end-to-end encryption so that the E2E key
between two clients is automatically renegotiated every 60 seconds. Everything
from the earlier phases still works, including server certificate validation,
proof of private key possession, Diffie-Hellman, the AES-256-GCM client-server
channel, and the inner E2E layer.

The server is not modified for Phase 5. It still relays E2E messages as opaque
text.

## What was added

- a rekey timer in the client that rotates every active E2E session after 60
  seconds
- rotation bookkeeping in the session, including the last key install time and
  rotation counter
- one previous key generation kept only for decryption during the transition
  between keys
- a log line printed on every successful key installation with a timestamp and
  key fingerprint

## How the 60-second rotation works

There is one timer thread in `client.cpp` (`rekey_timer`), not one thread per
peer. It wakes up once a second and checks which peers are due for rotation:

```cpp
mgr->peers_due_for_rotation(60)
```

A peer is due if it has a usable key, has no handshake already pending, and its
last key installation was 60 or more seconds ago. The pending-handshake check
prevents the timer from starting another rotation for the same peer while one is
already in progress.

For each due peer, the timer performs the same operation as the `/e2e` command:
it calls `start()` and sends the resulting INIT through the normal server
relay. The thread stops when the client exits and is joined before the socket is
closed.

## Reusing the existing handshake

No new wire tags were added. Rotation reuses `__E2E_INIT__` and `__E2E_ACK__`.
Each rotation generates a completely fresh DH keypair using the existing
`dh::KeyPair`, so the new key is independently generated rather than derived
from the old key.

## How the new key replaces the old one

The commit points remain the same as in Phase 4:

- the responder installs the new key when it processes the INIT
- the initiator installs the new key when it processes the ACK

`Session::install()` first copies the current key into a `prev_key` slot and
then installs the new key. It also records the installation time and increments
the rotation counter.

While a rotation handshake is still pending, the existing current key remains
usable, so chat is not interrupted while waiting for the ACK.

## Simultaneous rotations

Since both clients run their own 60-second timer, they can start a new
handshake at almost the same time. The simultaneous-handshake case uses the
same tie-break rule as Phase 4:

**the lexicographically lower username wins the initiator role.**

If a client receives an INIT while its own handshake is pending:

- if its username is lower, it keeps its own handshake and ignores the peer's
  INIT
- if its username is higher, it drops its own pending handshake and responds to
  the peer's INIT

Both clients make the same decision from the two usernames, so only one
handshake survives and both clients derive the same new key.

## Keeping chat working during a rotation

The two clients do not install the new key at exactly the same instant. The
responder installs it after receiving the INIT, while the initiator continues
using the old key until it receives the ACK.

To handle messages that are already in transit during this small transition
window, each session keeps one previous key:

- the current key is always used for encryption
- the previous key is never used for encryption
- incoming messages are first checked with the current key
- if authentication fails, the previous key is tried once
- only one previous generation is kept and it is replaced on the next rotation

## Rotation log

Every successful key installation prints a line similar to:

```text
[E2E-ROTATE] 2026-09-02 18:07:49 peer=bob rotation=#1 fingerprint=3671 0B36 04E2 4EE6
```

The log contains:

- the time of the key installation
- the peer username
- the rotation number
- a locally computed key fingerprint

The key itself is never printed.

## Building

Install the required packages:

```bash
sudo apt install -y g++ make libssl-dev
```

Build the project:

```bash
make clean
make
```

Generate the CA and server certificate on the server machine:

```bash
make certs IP=192.168.64.2
```

Copy `ca-cert.pem` to both client machines. The server private key should remain
on the server machine.

## Running

Start the server:

```bash
./server
```

Start each client:

```bash
./client 192.168.64.2 5000
```

The client commands are:

```text
@username message   send a message and select that user
/chat username      select a user without sending a message
/e2e username       start an E2E key exchange
/who                list online users
/quit               disconnect and exit
```

## Offline tests

Run:

```bash
./e2e_test
make check
```

## Reproducing the Phase 5 experiment

1. Start the server on the server VM.
2. Start Bob's client and register as `bob`.
3. Start Alice's client and register as `alice`.
4. From Alice, start an E2E session:

   ```text
   /e2e bob
   ```

5. Both clients should establish the session and print matching fingerprints.
6. Leave both clients running. A new rotation should occur every 60 seconds.
7. Wait until at least three key installations/rotations are visible, showing
   different fingerprints across rotations and matching fingerprints on both
   clients.
8. Immediately after rotation 3, send a message from Alice:

   ```text
   @bob message immediately after rotation 3
   ```

9. Bob should receive and decrypt the message correctly.

In the experiment, the fingerprints changed for each rotation and matched
between Alice and Bob. A message sent immediately after rotation 3 was also
received successfully.
