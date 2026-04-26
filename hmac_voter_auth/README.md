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

Follow this sequence strictly:

1. Initialize Receiver
Open http://localhost:8081

2. Set the Salt
Enter the shared salt and click "Set Salt"

3. Initialize Sender
Open http://localhost:8080

4. Configure Payload
- Enter Original Message
- Optionally modify Tampered Message to simulate a MitM attack (leave identical for secure transmission)
- Enter the same salt used by the receiver
- Set Receiver IP (use 127.0.0.1 locally)

5. Transmit
Click "Compute & Send"

Sender computes SHA-256 of:
Original Message + Salt

Then sends:
Tampered Message | Original Hash

6. Verification
Receiver computes its own hash using:
Received Message + Local Salt

- Match → message accepted
- Mismatch → tampering detected

## Architecture Notes

Frontend:
- HTML/JavaScript served directly by the C backend
- Uses HTTP GET/POST for communication

Backend:
- Multi-threaded C application
- Uses pthread for concurrency
- Runs HTTP server and TCP listener in parallel
- Cryptography handled using OpenSSL (EVP_sha256)