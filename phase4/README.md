# Phase 4 – End-to-End Encryption

## Overview

Phase 4 extends the Phase 3 secure chat system by adding end-to-end (E2E) encryption between clients.

Phase 3 already provides:

* TCP communication
* Diffie-Hellman key exchange between each client and the server
* AES-GCM encryption for client-server communication
* Server authentication using PKI
* Certificate validation
* Proof of private-key possession

However, in the Phase 3 architecture, the server decrypts messages received from one client before relaying them to another client. Therefore, the server can read user messages.

Phase 4 adds a second layer of encryption directly between communicating clients. The server continues to provide authenticated and encrypted transport, but it cannot read the plaintext of E2E-protected messages.

---

## Architecture

Phase 4 uses two layers of encryption.

### Outer Layer: Client ↔ Server

Each client establishes an authenticated secure channel with the server using:

* Server certificate validation
* Proof of private-key possession
* Diffie-Hellman key exchange
* AES-GCM encryption

This is inherited from Phase 3.

### Inner Layer: Client ↔ Client

When two clients establish an E2E session, they perform a separate Diffie-Hellman key exchange.

The resulting shared secret is used to derive an E2E session key.

Messages protected by this key are encrypted using AES-256-GCM before being sent to the server.

Therefore, the message has the following logical structure:

Client A
↓
E2E Encrypt
↓
Encrypted Client-Server Channel
↓
Server
↓
Encrypted Client-Server Channel
↓
Client B
↓
E2E Decrypt

The server can relay the E2E ciphertext but cannot decrypt the E2E plaintext.

---

## E2E Commands

### Start an E2E Session

```text
/e2e username
```

Example:

```text
/e2e bob
```

The initiating client starts an E2E Diffie-Hellman key exchange with the specified user.

After successful establishment, both clients display the same E2E key fingerprint.

Example:

```text
[E2E] Session with bob established (initiator).
[E2E] Key fingerprint: D254 A180 67E6 B5D2
```

The other client displays:

```text
[E2E] Session with alice established (responder).
[E2E] Key fingerprint: D254 A180 67E6 B5D2
```

Matching fingerprints demonstrate that both clients derived the same E2E session key.

---

## E2E Protocol Messages

The E2E key establishment and encrypted message transport use the following protocol messages:

* `__E2E_INIT__`
* `__E2E_ACK__`
* `__E2E_MSG__`

The server relays these messages between clients but does not possess the client-to-client E2E session key.

---

## Building

### Server VM

The server VM contains the server-side source files.

Build the server using:

```bash
cd ~/phase4
make clean
make server
```

Run the server:

```bash
./server
```

The server listens on port 5000.

### Client VMs

The client VMs contain the client and E2E source files.

Build the client:

```bash
cd ~/phase4
make clean
make client
```

Build the E2E test program:

```bash
make e2e_test
```

Run the client:

```bash
./client
```

---

## Running the System

### 1. Start the Server

On the server VM:

```bash
cd ~/phase4
./server
```

### 2. Start Client 1

On Client 1:

```bash
cd ~/phase4
./client
```

Enter:

```text
alice
```

### 3. Start Client 2

On Client 2:

```bash
cd ~/phase4
./client
```

Enter:

```text
bob
```

Both clients validate the server certificate and establish their individual authenticated encrypted channels with the server.

### 4. Establish E2E Encryption

From Alice:

```text
/e2e bob
```

Both Alice and Bob should report successful E2E session establishment and display matching E2E key fingerprints.

### 5. Send an E2E-Protected Message

After establishing an E2E session, messages between Alice and Bob are protected using the client-to-client E2E session key.

The server relays the E2E ciphertext but cannot recover the plaintext.

---

## Security Properties Demonstrated

### Server Authentication

Clients validate the server certificate and verify proof of private-key possession before establishing the client-server secure channel.

### Confidential Client-Server Communication

The communication between each client and the server is protected using Diffie-Hellman key establishment and AES-GCM encryption.

### End-to-End Confidentiality

Alice and Bob establish an additional Diffie-Hellman shared secret directly between themselves.

The resulting E2E key is used for AES-256-GCM encryption of E2E messages.

### Opaque Server Relay

The server can relay E2E messages but cannot decrypt the inner E2E ciphertext.

This is demonstrated by comparing normal Phase 3-style messages, which the server can read after decrypting the client-server channel, with Phase 4 E2E messages, where the server only observes opaque encrypted data.

### Bidirectional E2E Communication

Both participants can successfully encrypt and decrypt messages using the shared E2E session.

---

## Experimental Evidence

The following screenshots are included in the `evidence/` directory.

### P4_01_Before_E2E_Server_Reads_Plaintext.png

Demonstrates the baseline behavior before E2E encryption.

Alice sends messages to Bob through the normal client-server chat mechanism, and the server can read the plaintext after decrypting the client-server connection.

### P4_02_E2E_Handshake_Matching_Fingerprints.png

Demonstrates successful E2E session establishment between Alice and Bob.

Both clients display the same E2E key fingerprint, showing that they derived the same E2E session key.

### P4_03_E2E_Encrypted_Message_Opaque_Server.png

Demonstrates an E2E-encrypted message.

The receiving client successfully decrypts the message, while the server only relays opaque encrypted E2E data.

### P4_04_Bidirectional_E2E_Encrypted_Reply.png

Demonstrates successful bidirectional E2E communication.

Both Alice and Bob can send and decrypt messages using the established E2E session.

---

## Files Added for Phase 4

* `e2e.h` – E2E protocol and session definitions
* `e2e.cpp` – E2E key exchange and encryption implementation
* `e2e_test.cpp` – E2E functionality tests
* Updated `client.cpp` – E2E commands and message handling
* Updated `Makefile` – Build support for E2E components

---

## Notes

Phase 4 preserves the authenticated client-server security mechanisms from Phase 3 while adding an independent client-to-client encryption layer.

The server remains responsible for connection handling and message relay, but the E2E session key is established between the communicating clients and is not available to the server.
