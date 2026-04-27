# HMAC Voter Authentication System

This project is a C-based client-server application that demonstrates secure message authentication using SHA-256 hashes combined with a shared secret (salt). It features a web-based frontend and includes a Man-in-the-Middle (MitM) simulation to test the integrity of the hashing mechanism.

## Prerequisites

The server requires:
- A C compiler
- OpenSSL development libraries

### Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y libssl-dev build-essential

Alternatively:
make install-deps

### Fedora / RHEL / CentOS
sudo yum install -y openssl-devel gcc make

Alternatively:
make install-deps-rhel

## Build Instructions

make clean
make

## Running the Application

The system requires two separate instances:
- Sender
- Receiver

Run them in separate terminals.

### 1. Start the Receiver
./server receiver

Web interface: http://localhost:8081
TCP listener: port 9090

### 2. Start the Sender
./server sender

Web interface: http://localhost:8080

## Usage Workflow

Follow this sequence strictly to test the transmission and buffering mechanism:

1. Initialize Receiver
Open http://localhost:8081. (Note: The receiver will securely buffer incoming data over TCP but will not verify or display the message contents until a salt is explicitly provided).

2. Initialize Sender
Open http://localhost:8080

3. Configure Payload
- Enter Original Message (e.g., "Vote for candidate A")
- Optionally modify Tampered Message to simulate a MitM attack (leave identical for secure transmission)
- Enter the shared salt
- Set Receiver IP (use 127.0.0.1 locally)

4. Transmit
Click "Compute & Send"

Sender computes SHA-256 of:
Original Message + Salt

Then sends:
Tampered Message | Original Hash over TCP.

5. Payload Buffering
The receiver node ingests the incoming TCP payload and holds it in a secure buffer. If you click "Check Status" now without setting a salt, the system will enforce security by prompting that the payload is buffered and requires a salt to proceed.

6. Set Salt and Verify
On the Receiver interface:
- Enter the shared salt and click "Set Salt"
- Click "Check Status"

The receiver now computes its own hash dynamically using:
Buffered Received Message + Local Salt

The interface will then reveal the full payload details and comparison:
- Received message: (Displays the tampered or secure message)
- Received hash: (The hash sent over the network)
- Receiver salt: (The local salt just provided)
- Recalculated hash: (The hash generated locally by the receiver)
- Result: 
    - Match Valid (Green text) -> Hashes match, message accepted.
    - No Match (MitM Detected) (Red text) -> Hashes mismatch, tampering detected.

## Architecture Notes

Frontend:
- HTML/JavaScript served directly by the C backend
- Uses HTTP GET/POST for communication
- Auto-refresh disabled; manual polling for status updates to enforce explicit verification

Backend:
- Multi-threaded C application
- Uses pthread for concurrency
- Runs HTTP server and TCP listener in parallel
- Cryptography handled using OpenSSL (EVP_sha256)
- Secure payload buffering mechanism before hash recomputation to enforce salt validation