# Phase 1 - Basic TCP Chat Application

This phase implements a simple TCP-based chat application with one server and up to two clients.

The server allows clients to register with a username, see the connected users, and send messages to each other.

## Files

* `server.cpp` - TCP chat server
* `client.cpp` - TCP chat client

## Features

* TCP connection between clients and server
* Username registration
* Maximum of two connected clients
* List online users using `/who`
* Send messages using `@username message`
* Select a chat partner using `/chat username`
* Send messages directly to the selected chat partner
* Disconnect using `/quit`
* Separate thread for receiving messages while the user can continue typing
* Server logs messages in plaintext

## Building

### Server

```bash
g++ -std=c++17 server.cpp -o server -pthread
```

### Client

```bash
g++ -std=c++17 client.cpp -o client -pthread
```

## Running

Start the server first:

```bash
./server
```

The server listens on port `5000`.

Then start the client on each client machine:

```bash
./client
```

Enter a different username for each client.

## Client Commands

### Send a message to a specific user

```text
@username message
```

Example:

```text
@bob Hello Bob
```

### Select a chat partner

```text
/chat username
```

Example:

```text
/chat bob
```

After selecting a chat partner, normal text messages are sent directly to that user.

### List online users

```text
/who
```

### Quit

```text
/quit
```

## Message Flow

The client sends messages to the server using the following format:

```text
MSG|recipient|message
```

The server forwards the message to the recipient as:

```text
FROM|sender|message
```

The server can read and log the original message text in this phase because no encryption is used yet.

