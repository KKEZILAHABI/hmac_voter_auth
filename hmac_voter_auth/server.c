#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

#define MAX_BUFFER_SIZE 4096
#define HTTP_PORT 8080
#define TCP_PORT 9090

/*
 * HMAC Voter Authentication System
 * 
 * This system implements a secure message authentication protocol using HMAC (Hash-based Message Authentication Code)
 * with SHA-256 as the hash function. The system operates in two modes:
 * 
 * Sender Mode: Computes H(M || S) where M is the message and S is the shared secret
 * Receiver Mode: Recomputes H(M || S) and verifies hash integrity
 * 
 * Security Properties:
 * - Message Integrity: Any modification to M changes the hash
 * - Authentication: Only parties with secret S can compute valid hashes
 * - Non-repudiation: Sender cannot deny sending authenticated messages
 */

/*
 * Authentication result structure for storing verification outcomes
 * Used in receiver mode to maintain state between TCP reception and HTTP status queries
 */
typedef struct {
    char result[64];      // "Match ✓" or "No Match ✗"
    char hash[65];        // Received SHA-256 hash in hex format
    char message[MAX_BUFFER_SIZE];  // Original message content
    int is_valid;        // Boolean flag for verification success
} AuthResult;

/*
 * Dynamic secret storage for receiver mode
 * Allows receiver to set secret via web interface instead of hardcoding
 */
typedef struct {
    char secret[256];    // Shared secret key
    int is_set;          // Boolean flag indicating if secret has been set
} SecretStorage;

AuthResult global_result = {0};  // Global storage for receiver state
SecretStorage global_secret = {0};  // Global storage for receiver secret

/*
 * Compute SHA-256 hash using OpenSSL EVP interface
 * 
 * This function implements the core cryptographic primitive for our HMAC system.
 * SHA-256 produces a 256-bit (32-byte) hash value, providing
 * strong collision resistance and preimage resistance.
 * 
 * Parameters:
 *   data - Input data to be hashed
 *   data_len - Length of input data in bytes
 *   hash - Output buffer (32 bytes) for binary hash
 */
void compute_sha256(const char *data, int data_len, unsigned char *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    
    EVP_MD_CTX_free(mdctx);
}

/*
 * Convert binary SHA-256 hash to hexadecimal string representation
 * 
 * SHA-256 produces 32 bytes of binary output. This function converts
 * each byte to 2 hexadecimal characters, resulting in a 64-character string.
 * Hexadecimal representation is used for network transmission and display.
 * 
 * Parameters:
 *   hash - 32-byte binary hash input
 *   hex_string - 65-byte output buffer (64 chars + null terminator)
 */
void hash_to_hex(const unsigned char *hash, char *hex_string) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[64] = '\0';
}

/*
 * Send HTTP response with proper CORS headers
 * 
 * This function constructs a complete HTTP response including:
 * - Status code (200 OK, 400 Bad Request, etc.)
 * - Content-Type header for proper client interpretation
 * - CORS headers to allow cross-origin requests from browsers
 * - Content-Length header for proper HTTP protocol compliance
 */
void send_http_response(int client_fd, const char *status_code, const char *content_type, const char *body) {
    char response[MAX_BUFFER_SIZE];
    snprintf(response, sizeof(response), 
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type\r\n"
             "\r\n%s",
             status_code, content_type, strlen(body), body);
    send(client_fd, response, strlen(response), 0);
}

/*
 * Serve index.html file from current directory
 * 
 * This function reads and serves the HTML interface file.
 * Returns 404 if file doesn't exist.
 * 
 * Parameters:
 *   client_fd - HTTP client socket descriptor
 */
void serve_index_html(int client_fd) {
    FILE *file = fopen("index.html", "r");
    if (!file) {
        send_http_response(client_fd, "404 Not Found", "text/html", 
                          "<html><body><h1>404 - index.html not found</h1></body></html>");
        return;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Read file content
    char *content = malloc(file_size + 1);
    if (!content) {
        fclose(file);
        send_http_response(client_fd, "500 Internal Server Error", "text/html", 
                          "<html><body><h1>500 - Memory allocation failed</h1></body></html>");
        return;
    }
    
    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);
    
    send_http_response(client_fd, "200 OK", "text/html", content);
    free(content);
}

/*
 * Parse JSON request body to extract authentication parameters
 * 
 * This function extracts three critical fields from the JSON payload:
 * - message: The content to be authenticated and transmitted
 * - secret: Shared secret key for HMAC computation
 * - receiver_ip: Destination IP address for TCP transmission
 * 
 * The function uses simple string parsing rather than a full JSON library
 * to minimize dependencies in this educational implementation.
 * 
 * Parameters:
 *   body - JSON string from HTTP POST request
 *   message - Output buffer for extracted message content
 *   secret - Output buffer for extracted secret key
 *   receiver_ip - Output buffer for extracted IP address
 * 
 * Returns: 1 on success, 0 on parsing failure
 */
int parse_json_body(const char *body, char *message, char *secret, char *receiver_ip) {
    printf("[DEBUG] Parsing JSON body: %.200s...\n", body);
    
    char *msg_start = strstr(body, "\"message\":\"");
    char *secret_start = strstr(body, "\"secret\":\"");
    char *ip_start = strstr(body, "\"receiver_ip\":\"");
    
    printf("[DEBUG] Found fields - msg: %s, secret: %s, ip: %s\n", 
           msg_start ? "yes" : "no", secret_start ? "yes" : "no", ip_start ? "yes" : "no");
    
    if (!msg_start || !secret_start || !ip_start) return 0;
    
    msg_start += 11;  // Skip "message\":\" (11 chars)
    secret_start += 10; // Skip "secret\":\" (10 chars)
    ip_start += 15;    // Skip "receiver_ip\":\" (15 chars)
    
    printf("[DEBUG] After offset - msg_start: %.20s..., secret_start: %.20s..., ip_start: %.20s...\n", 
           msg_start, secret_start, ip_start);
    
    char *msg_end = strstr(msg_start, "\"");
    char *secret_end = strstr(secret_start, "\"");
    char *ip_end = strstr(ip_start, "\"");
    
    printf("[DEBUG] Found end quotes - msg_end: %s, secret_end: %s, ip_end: %s\n",
           msg_end ? "yes" : "no", secret_end ? "yes" : "no", ip_end ? "yes" : "no");
    
    if (!msg_end || !secret_end || !ip_end) return 0;
    
    int msg_len = msg_end - msg_start;
    int secret_len = secret_end - secret_start;
    int ip_len = ip_end - ip_start;
    
    printf("[DEBUG] String lengths - msg: %d, secret: %d, ip: %d\n", msg_len, secret_len, ip_len);
    
    strncpy(message, msg_start, msg_len);
    message[msg_len] = '\0';
    
    strncpy(secret, secret_start, secret_len);
    secret[secret_len] = '\0';
    
    strncpy(receiver_ip, ip_start, ip_len);
    receiver_ip[ip_len] = '\0';
    
    printf("[DEBUG] Parsed - message: '%s', secret: '%s', ip: '%s'\n", message, secret, receiver_ip);
    
    return 1;
}

/*
 * Parse JSON request body to extract secret only
 * 
 * This function is used for the /set_secret endpoint to extract
 * just the secret field from the JSON payload.
 * 
 * Parameters:
 *   body - JSON string from HTTP POST request
 *   secret - Output buffer for extracted secret key
 * 
 * Returns: 1 on success, 0 on parsing failure
 */
int parse_secret_body(const char *body, char *secret) {
    printf("[DEBUG] Parsing secret body: %.200s...\n", body);
    
    char *secret_start = strstr(body, "\"secret\":\"");
    
    printf("[DEBUG] Found secret field: %s\n", secret_start ? "yes" : "no");
    
    if (!secret_start) return 0;
    
    secret_start += 10; // Skip "secret\":\" (10 chars)
    
    char *secret_end = strstr(secret_start, "\"");
    if (!secret_end) return 0;
    
    int secret_len = secret_end - secret_start;
    
    strncpy(secret, secret_start, secret_len);
    secret[secret_len] = '\0';
    
    printf("[DEBUG] Parsed secret: '%s'\n", secret);
    
    return 1;
}

/*
 * Handle HTTP POST requests in sender mode
 * 
 * This function implements the core sender functionality:
 * 1. Extracts authentication parameters from JSON
 * 2. Computes HMAC: H(M || S) where M is message and S is secret
 * 3. Establishes TCP connection to receiver
 * 4. Transmits message|hash for verification
 * 
 * The concatenation M || S (message concatenated with secret) is a simple
 * HMAC construction. In production, you would use proper HMAC with key separation.
 * 
 * Parameters:
 *   client_fd - HTTP client socket descriptor
 *   body - JSON request body containing message, secret, and receiver_ip
 */
void handle_sender_post(int client_fd, const char *body) {
    char message[MAX_BUFFER_SIZE] = {0};
    char secret[256] = {0};
    char receiver_ip[64] = {0};
    
    // Extract authentication parameters from JSON request
    if (!parse_json_body(body, message, secret, receiver_ip)) {
        send_http_response(client_fd, "400 Bad Request", "application/json", 
                          "{\"error\":\"Invalid JSON format - need message, secret, and receiver_ip\"}");
        return;
    }
    
    // Compute HMAC: H(M || S) using SHA-256
    // Note: This simple concatenation is for educational purposes.
    // Production systems should use proper HMAC with key separation.
    char combined[MAX_BUFFER_SIZE + 256];
    snprintf(combined, sizeof(combined), "%s%s", message, secret);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(combined, strlen(combined), hash);
    
    char hex_hash[65];
    hash_to_hex(hash, hex_hash);
    
    // Transmit authenticated message to receiver via TCP
    printf("[DEBUG] Attempting TCP connection to %s:%d\n", receiver_ip, TCP_PORT);
    
    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket < 0) {
        printf("[DEBUG] Failed to create TCP socket\n");
        send_http_response(client_fd, "500 Internal Server Error", "application/json",
                          "{\"error\":\"Failed to create TCP socket\"}");
        return;
    }
    
    // Establish TCP connection to receiver
    struct sockaddr_in receiver_addr;
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(TCP_PORT);
    inet_pton(AF_INET, receiver_ip, &receiver_addr.sin_addr);
    
    printf("[DEBUG] Connecting to receiver...\n");
    if (connect(tcp_socket, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr)) < 0) {
        printf("[DEBUG] Connection failed to %s:%d\n", receiver_ip, TCP_PORT);
        close(tcp_socket);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "{\"error\":\"Could not connect to receiver at %s\"}", receiver_ip);
        send_http_response(client_fd, "500 Internal Server Error", "application/json", error_msg);
        return;
    }
    
    printf("[DEBUG] Connected to receiver successfully\n");
    
    // Transmit message|hash payload to receiver
    // The pipe character '|' separates message from hash for simple parsing
    char tcp_message[MAX_BUFFER_SIZE + 65];
    snprintf(tcp_message, sizeof(tcp_message), "%s|%s", message, hex_hash);
    send(tcp_socket, tcp_message, strlen(tcp_message), 0);
    close(tcp_socket);
    
    // Return success response to HTTP client
    char response[256];
    snprintf(response, sizeof(response), 
             "{\"status\":\"sent\",\"hash\":\"%s\"}", hex_hash);
    send_http_response(client_fd, "200 OK", "application/json", response);
    
    printf("[SENDER] Message sent to %s: %s\n", receiver_ip, message);
}

/*
 * Handle incoming TCP connections in receiver mode
 * 
 * This function processes authenticated messages from the sender:
 * 1. Receives message|hash payload via TCP
 * 2. Parses the pipe-separated format
 * 3. Recomputes H(M || S) using stored secret
 * 4. Compares hashes for integrity verification
 * 5. Stores result for HTTP status queries
 * 
 * The receiver must know the same secret as the sender for verification.
 * This demonstrates the symmetric nature of HMAC authentication.
 * 
 * Parameters:
 *   client_fd - TCP client socket descriptor from sender
 */
void handle_receiver_tcp(int client_fd) {
    char buffer[MAX_BUFFER_SIZE] = {0};
    int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received <= 0) {
        close(client_fd);
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    // Parse message|hash format using pipe separator
    char *separator = strchr(buffer, '|');
    if (!separator) {
        close(client_fd);
        return;
    }
    
    *separator = '\0';
    char *message = buffer;
    char *received_hash = separator + 1;
    
    // Check if secret has been set
    if (!global_secret.is_set) {
        strcpy(global_result.result, "No Match \u2717 (Secret not set)");
        global_result.is_valid = 0;
        strcpy(global_result.hash, received_hash);
        strncpy(global_result.message, message, MAX_BUFFER_SIZE - 1);
        global_result.message[MAX_BUFFER_SIZE - 1] = '\0';
        
        printf("[RECEIVER] Received: %s -> %s\n", message, global_result.result);
        close(client_fd);
        return;
    }
    
    // Recompute HMAC using stored secret key
    char combined[MAX_BUFFER_SIZE + 256];
    snprintf(combined, sizeof(combined), "%s%s", message, global_secret.secret);
    
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    compute_sha256(combined, strlen(combined), computed_hash);
    
    char computed_hex[65];
    hash_to_hex(computed_hash, computed_hex);
    
    // Compare received hash with computed hash for integrity verification
    // This is the core authentication check - prevents tampering
    if (strcmp(received_hash, computed_hex) == 0) {
        strcpy(global_result.result, "Match \u2713");
        global_result.is_valid = 1;
    } else {
        strcpy(global_result.result, "No Match \u2717");
        global_result.is_valid = 0;
    }
    
    // Store verification results for HTTP status queries
    strcpy(global_result.hash, received_hash);
    strncpy(global_result.message, message, MAX_BUFFER_SIZE - 1);
    global_result.message[MAX_BUFFER_SIZE - 1] = '\0';
    
    printf("[RECEIVER] Received: %s -> %s\n", message, global_result.result);
    close(client_fd);
}

/*
 * Handle HTTP GET status requests in receiver mode
 * 
 * This function provides the verification results to web browsers:
 * - Returns authentication status (Match/No Match)
 * - Shows the original message and received hash
 * - Allows real-time monitoring of authentication attempts
 * 
 * This enables separation between TCP reception (from sender)
 * and HTTP queries (from browser) for flexible deployment.
 * 
 * Parameters:
 *   client_fd - HTTP client socket descriptor
 */
void handle_receiver_status(int client_fd) {
    char response[MAX_BUFFER_SIZE];
    
    if (global_result.is_valid || strlen(global_result.message) > 0) {
        snprintf(response, sizeof(response),
                 "{\"result\":\"%s\",\"hash\":\"%s\",\"message\":\"%s\"}",
                 global_result.result, global_result.hash, global_result.message);
    } else {
        snprintf(response, sizeof(response),
                 "{\"result\":\"No data received yet\"}");
    }
    
    send_http_response(client_fd, "200 OK", "application/json", response);
}

/*
 * Handle GET /mode endpoint
 * 
 * Returns the current server mode (sender or receiver).
 * This allows the frontend to dynamically adapt the interface.
 * 
 * Parameters:
 *   client_fd - HTTP client socket descriptor
 *   mode - Server mode (1=sender, 2=receiver)
 */
void handle_get_mode(int client_fd, int mode) {
    char response[MAX_BUFFER_SIZE];
    
    if (mode == 1) {
        snprintf(response, sizeof(response),
                 "{\"mode\":\"sender\"}");
    } else {
        snprintf(response, sizeof(response),
                 "{\"mode\":\"receiver\"}");
    }
    
    send_http_response(client_fd, "200 OK", "application/json", response);
}

/*
 * Handle GET /secret endpoint
 * 
 * Returns whether a secret has been set for the receiver.
 * This allows the frontend to check if a secret is configured.
 * 
 * Parameters:
 *   client_fd - HTTP client socket descriptor
 */
void handle_get_secret(int client_fd) {
    char response[MAX_BUFFER_SIZE];
    
    if (global_secret.is_set) {
        snprintf(response, sizeof(response),
                 "{\"secret_set\":true}");
    } else {
        snprintf(response, sizeof(response),
                 "{\"secret_set\":false}");
    }
    
    send_http_response(client_fd, "200 OK", "application/json", response);
}

/*
 * Handle POST /set_secret endpoint
 * 
 * Sets the shared secret for HMAC verification.
 * This allows the receiver to configure the secret via web interface.
 * 
 * Parameters:
 *   client_fd - HTTP client socket descriptor
 *   body - JSON request body containing the secret
 */
void handle_set_secret(int client_fd, const char *body) {
    char secret[256] = {0};
    
    // Extract secret from JSON request
    if (!parse_secret_body(body, secret)) {
        send_http_response(client_fd, "400 Bad Request", "application/json", 
                          "{\"error\":\"Invalid JSON format - need secret\"}");
        return;
    }
    
    // Store the secret
    strncpy(global_secret.secret, secret, sizeof(global_secret.secret) - 1);
    global_secret.secret[sizeof(global_secret.secret) - 1] = '\0';
    global_secret.is_set = 1;
    
    printf("[RECEIVER] Secret set: %s\n", secret);
    
    send_http_response(client_fd, "200 OK", "application/json", 
                      "{\"status\":\"secret_set\"}");
}

/*
 * HTTP server thread - handles web interface requests
 * 
 * This thread manages the HTTP server that provides:
 * - Sender interface: Accepts POST requests with authentication data
 * - Receiver interface: Accepts GET requests for verification status
 * - CORS support: Enables cross-origin browser requests
 * 
 * The server handles both modes in a single thread for simplicity.
 * In production, you might use separate processes or more sophisticated threading.
 * 
 * Parameters:
 *   arg - Pointer to server mode (1=sender, 2=receiver)
 */
void* http_server(void* arg) {
    int mode = *(int*)arg;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("HTTP socket creation failed");
        return NULL;
    }
    
    // Configure server socket for HTTP interface
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(HTTP_PORT);
    
    // Bind socket to HTTP port
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("HTTP bind failed");
        close(server_fd);
        return NULL;
    }
    
    // Start listening for HTTP connections
    if (listen(server_fd, 5) < 0) {
        perror("HTTP listen failed");
        close(server_fd);
        return NULL;
    }
    
    printf("[HTTP] Server listening on port %d (mode: %s)\n", 
           HTTP_PORT, mode == 1 ? "SENDER" : "RECEIVER");
    
    // Main request handling loop
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        char buffer[MAX_BUFFER_SIZE] = {0};
        int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            
            printf("[DEBUG] Received request (mode %d): %.100s...\n", mode, buffer);
            
            // Handle CORS preflight requests for browser compatibility
            if (strstr(buffer, "OPTIONS /") || strstr(buffer, "OPTIONS /status") || 
                strstr(buffer, "OPTIONS /send") || strstr(buffer, "OPTIONS /secret") || 
                strstr(buffer, "OPTIONS /set_secret") || strstr(buffer, "OPTIONS /mode")) {
                printf("[DEBUG] Handling OPTIONS request\n");
                send_http_response(client_fd, "200 OK", "text/plain", "");
            } 
            // Serve index.html for root GET requests
            else if (strstr(buffer, "GET / HTTP/1.1") || strstr(buffer, "GET / HTTP/1.0")) {
                printf("[DEBUG] Serving index.html\n");
                serve_index_html(client_fd);
            }
            // Sender mode: Handle POST /send endpoint
            else if (mode == 1 && strstr(buffer, "POST /send")) {
                printf("[DEBUG] Handling POST /send request in sender mode\n");
                // Extract JSON body from HTTP request
                char *body_start = strstr(buffer, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    printf("[DEBUG] Found body: %.100s...\n", body_start);
                    handle_sender_post(client_fd, body_start);
                } else {
                    printf("[DEBUG] No request body found\n");
                    send_http_response(client_fd, "400 Bad Request", "application/json", 
                                      "{\"error\":\"No request body found\"}");
                }
            }
            // Receiver mode: Handle GET /status endpoint
            else if (mode == 2 && strstr(buffer, "GET /status")) {
                printf("[DEBUG] Handling GET /status request in receiver mode\n");
                handle_receiver_status(client_fd);
            }
            // Handle GET /mode endpoint (both modes)
            else if (strstr(buffer, "GET /mode")) {
                printf("[DEBUG] Handling GET /mode request\n");
                handle_get_mode(client_fd, mode);
            }
            // Receiver mode: Handle GET /secret endpoint
            else if (mode == 2 && strstr(buffer, "GET /secret")) {
                printf("[DEBUG] Handling GET /secret request in receiver mode\n");
                handle_get_secret(client_fd);
            }
            // Receiver mode: Handle POST /set_secret endpoint
            else if (mode == 2 && strstr(buffer, "POST /set_secret")) {
                printf("[DEBUG] Handling POST /set_secret request in receiver mode\n");
                // Extract JSON body from HTTP request
                char *body_start = strstr(buffer, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    printf("[DEBUG] Found body: %.100s...\n", body_start);
                    handle_set_secret(client_fd, body_start);
                } else {
                    printf("[DEBUG] No request body found\n");
                    send_http_response(client_fd, "400 Bad Request", "application/json", 
                                      "{\"error\":\"No request body found\"}");
                }
            }
            // Sender mode: Handle GET /status endpoint (for compatibility)
            else if (mode == 1 && strstr(buffer, "GET /status")) {
                printf("[DEBUG] Handling GET /status request in sender mode\n");
                send_http_response(client_fd, "200 OK", "application/json", 
                                  "{\"status\":\"sender_mode\",\"message\":\"Use POST /send to send messages\"}");
            }
            // Receiver mode: Handle GET /status endpoint (for compatibility)
            else if (mode == 2 && strstr(buffer, "GET /status")) {
                printf("[DEBUG] Handling GET /status request in receiver mode\n");
                handle_receiver_status(client_fd);
            }
            // Handle unmatched routes
            else {
                printf("[DEBUG] No matching route found\n");
                send_http_response(client_fd, "404 Not Found", "application/json", 
                                  "{\"error\":\"Endpoint not found\"}");
            }
        }
        close(client_fd);
    }
    
    close(server_fd);
    return NULL;
}

/*
 * TCP server thread for receiver mode
 * 
 * This thread manages the TCP server that receives authenticated messages:
 * - Listens on port 9090 for incoming connections
 * - Handles multiple senders in sequence
 * - Processes message|hash format for verification
 * 
 * This separation of concerns allows:
 * - HTTP interface for web browsers (port 8080)
 * - TCP interface for sender applications (port 9090)
 * 
 * Parameters:
 *   arg - Unused (thread function requirement)
 */
void* tcp_server(void* arg) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Create TCP socket for receiver interface
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("TCP socket creation failed");
        return NULL;
    }
    
    // Configure socket for address reuse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);
    
    // Bind socket to TCP port
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP bind failed");
        close(server_fd);
        return NULL;
    }
    
    // Start listening for TCP connections
    if (listen(server_fd, 5) < 0) {
        perror("TCP listen failed");
        close(server_fd);
        return NULL;
    }
    
    printf("[TCP] Receiver listening on port %d\n", TCP_PORT);
    
    // Accept and process incoming connections
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        handle_receiver_tcp(client_fd);
    }
    
    close(server_fd);
    return NULL;
}

/*
 * Main entry point for HMAC Voter Authentication System
 * 
 * This function initializes the system and starts the appropriate mode:
 * - Sender Mode: HTTP server for accepting authentication requests
 * - Receiver Mode: HTTP server + TCP server for verification
 * 
 * The system demonstrates practical HMAC authentication with:
 * - SHA-256 cryptographic hash function
 * - Multi-threaded server architecture
 * - Web-based user interface
 * - Cross-network message transmission
 * 
 * Security Considerations:
 * - Secret key must be securely stored in production
 * - Use proper HMAC with key separation (not simple concatenation)
 * - Add message authentication codes for replay protection
 * - Implement rate limiting for DoS protection
 * 
 * Parameters:
 *   argc - Argument count (should be 2)
 *   argv - Arguments: program name and mode
 * 
 * Returns: 0 on success, 1 on error
 */
int main(int argc, char *argv[]) {
    // Validate command line arguments
    if (argc != 2) {
        printf("Usage: %s <sender|receiver>\n", argv[0]);
        printf("HMAC Voter Authentication System\n");
        printf("\nModes:\n");
        printf("  sender   - Accept authentication requests via HTTP POST\n");
        printf("  receiver - Accept messages via TCP, verify via HTTP GET\n");
        printf("\nExamples:\n");
        printf("  %s sender    # Start in sender mode\n", argv[0]);
        printf("  %s receiver  # Start in receiver mode\n", argv[0]);
        return 1;
    }
    
    // Initialize OpenSSL cryptographic library
    OpenSSL_add_all_algorithms();
    
    pthread_t http_thread, tcp_thread;
    int mode = 0;
    
    // Configure and start sender mode
    if (strcmp(argv[1], "sender") == 0) {
        mode = 1;  // Sender mode identifier
        printf("=== STARTING SENDER MODE ===\n");
        printf("Web Interface: http://localhost:8080\n");
        printf("Endpoints:\n");
        printf("  GET  /           - Serve index.html\n");
        printf("  POST /send       - Send authenticated message\n");
        printf("Expected JSON: {\"message\":\"your_message\",\"secret\":\"shared_secret\",\"receiver_ip\":\"target_ip\"}\n");
        
        // Start HTTP server thread for sender interface
        if (pthread_create(&http_thread, NULL, http_server, &mode) != 0) {
            perror("Failed to create HTTP thread");
            return 1;
        }
    } 
    // Configure and start receiver mode
    else if (strcmp(argv[1], "receiver") == 0) {
        mode = 2;  // Receiver mode identifier
        printf("=== STARTING RECEIVER MODE ===\n");
        printf("Web Interface: http://localhost:8080\n");
        printf("TCP Interface: Listening on port %d for incoming messages\n", TCP_PORT);
        printf("Endpoints:\n");
        printf("  GET  /           - Serve index.html\n");
        printf("  GET  /status     - Get verification results\n");
        printf("  GET  /secret     - Check if secret is set\n");
        printf("  POST /set_secret - Set shared secret\n");
        printf("Note: Secret must be set via /set_secret before verification\n");
        
        // Start HTTP server thread for status interface
        if (pthread_create(&http_thread, NULL, http_server, &mode) != 0) {
            perror("Failed to create HTTP thread");
            return 1;
        }
        
        // Start TCP server thread for message reception
        if (pthread_create(&tcp_thread, NULL, tcp_server, NULL) != 0) {
            perror("Failed to create TCP thread");
            return 1;
        }
    } 
    // Handle invalid mode parameter
    else {
        printf("Error: Invalid mode '%s'\n", argv[1]);
        printf("Valid modes: sender, receiver\n");
        return 1;
    }
    
    // Wait for server threads to complete (runs indefinitely)
    printf("\n[SYSTEM] Server started successfully. Press Ctrl+C to stop.\n");
    pthread_join(http_thread, NULL);
    if (mode == 2) {
        pthread_join(tcp_thread, NULL);
    }
    
    // Cleanup OpenSSL resources
    EVP_cleanup();
    
    printf("\n[SYSTEM] Server shutdown complete.\n");
    return 0;
}