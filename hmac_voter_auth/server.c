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

#define MAX_BUFFER_SIZE 4096
#define HTTP_PORT 8080
#define TCP_PORT 9090
#define RECEIVER_IP "192.168.1.100"  // Hardcoded IP for receiver

// Global storage for receiver mode (student project - simple approach)
typedef struct {
    char result[64];
    char hash[65];
    char message[MAX_BUFFER_SIZE];
    int is_valid;
} AuthResult;

AuthResult global_result = {0};

// Student comment: Helper function to compute SHA-256 hash
void compute_sha256(const char *data, int data_len, unsigned char *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    
    EVP_MD_CTX_free(mdctx);
}

// Student comment: Convert binary hash to hex string for display
void hash_to_hex(const unsigned char *hash, char *hex_string) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[64] = '\0';
}

// Student comment: Simple HTTP response helper with proper CORS headers
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

// Student comment: Parse JSON body to extract message, secret, and receiver_ip
int parse_json_body(const char *body, char *message, char *secret, char *receiver_ip) {
    printf("[DEBUG] Parsing JSON body: %.200s...\n", body);
    
    char *msg_start = strstr(body, "\"message\":\"");
    char *secret_start = strstr(body, "\"secret\":\"");
    char *ip_start = strstr(body, "\"receiver_ip\":\"");
    
    printf("[DEBUG] Found fields - msg: %s, secret: %s, ip: %s\n", 
           msg_start ? "yes" : "no", secret_start ? "yes" : "no", ip_start ? "yes" : "no");
    
    if (!msg_start || !secret_start || !ip_start) return 0;
    
    msg_start += 10;  // Skip "message":
    secret_start += 9; // Skip "secret":
    ip_start += 14;    // Skip "receiver_ip":
    
    char *msg_end = strstr(msg_start, "\"");
    char *secret_end = strstr(secret_start, "\"");
    char *ip_end = strstr(ip_start, "\"");
    
    if (!msg_end || !secret_end || !ip_end) return 0;
    
    int msg_len = msg_end - msg_start;
    int secret_len = secret_end - secret_start;
    int ip_len = ip_end - ip_start;
    
    strncpy(message, msg_start, msg_len);
    message[msg_len] = '\0';
    
    strncpy(secret, secret_start, secret_len);
    secret[secret_len] = '\0';
    
    strncpy(receiver_ip, ip_start, ip_len);
    receiver_ip[ip_len] = '\0';
    
    printf("[DEBUG] Parsed - message: '%s', secret: '%s', ip: '%s'\n", message, secret, receiver_ip);
    
    return 1;
}

// Student comment: Sender mode - handle HTTP POST from browser
void handle_sender_post(int client_fd, const char *body) {
    char message[MAX_BUFFER_SIZE] = {0};
    char secret[256] = {0};
    char receiver_ip[64] = {0};
    
    // Student comment: Extract message, secret, and receiver_ip from JSON
    if (!parse_json_body(body, message, secret, receiver_ip)) {
        send_http_response(client_fd, "400 Bad Request", "application/json", 
                          "{\"error\":\"Invalid JSON format - need message, secret, and receiver_ip\"}");
        return;
    }
    
    // Student comment: Compute H(M || S) using SHA-256
    char combined[MAX_BUFFER_SIZE + 256];
    snprintf(combined, sizeof(combined), "%s%s", message, secret);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(combined, strlen(combined), hash);
    
    char hex_hash[65];
    hash_to_hex(hash, hex_hash);
    
    // Student comment: Send to receiver via TCP
    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket < 0) {
        send_http_response(client_fd, "500 Internal Server Error", "application/json",
                          "{\"error\":\"Failed to create TCP socket\"}");
        return;
    }
    
    struct sockaddr_in receiver_addr;
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(TCP_PORT);
    inet_pton(AF_INET, receiver_ip, &receiver_addr.sin_addr);
    
    // Student comment: Try to connect to receiver using extracted IP
    if (connect(tcp_socket, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr)) < 0) {
        close(tcp_socket);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "{\"error\":\"Could not connect to receiver at %s\"}", receiver_ip);
        send_http_response(client_fd, "500 Internal Server Error", "application/json", error_msg);
        return;
    }
    
    // Student comment: Send message|hash format to receiver
    char tcp_message[MAX_BUFFER_SIZE + 65];
    snprintf(tcp_message, sizeof(tcp_message), "%s|%s", message, hex_hash);
    send(tcp_socket, tcp_message, strlen(tcp_message), 0);
    close(tcp_socket);
    
    // Student comment: Return success response to browser
    char response[256];
    snprintf(response, sizeof(response), 
             "{\"status\":\"sent\",\"hash\":\"%s\",\"receiver_ip\":\"%s\"}", hex_hash, receiver_ip);
    send_http_response(client_fd, "200 OK", "application/json", response);
    
    printf("[SENDER] Message sent to %s: %s\n", receiver_ip, message);
}

// Student comment: Receiver mode - handle incoming TCP from sender
void handle_receiver_tcp(int client_fd) {
    char buffer[MAX_BUFFER_SIZE] = {0};
    int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received <= 0) {
        close(client_fd);
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    // Student comment: Parse message|hash format
    char *separator = strchr(buffer, '|');
    if (!separator) {
        close(client_fd);
        return;
    }
    
    *separator = '\0';
    char *message = buffer;
    char *received_hash = separator + 1;
    
    // Student comment: Recompute hash with same secret (hardcoded for demo)
    char secret[256] = "shared_secret_123";  // In real app, this would be securely stored
    char combined[MAX_BUFFER_SIZE + 256];
    snprintf(combined, sizeof(combined), "%s%s", message, secret);
    
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    compute_sha256(combined, strlen(combined), computed_hash);
    
    char computed_hex[65];
    hash_to_hex(computed_hash, computed_hex);
    
    // Student comment: Compare hashes and store result
    if (strcmp(received_hash, computed_hex) == 0) {
        strcpy(global_result.result, "Match \u2713");
        global_result.is_valid = 1;
    } else {
        strcpy(global_result.result, "No Match \u2717");
        global_result.is_valid = 0;
    }
    
    strcpy(global_result.hash, received_hash);
    strncpy(global_result.message, message, MAX_BUFFER_SIZE - 1);
    global_result.message[MAX_BUFFER_SIZE - 1] = '\0';
    
    printf("[RECEIVER] Received: %s -> %s\n", message, global_result.result);
    close(client_fd);
}

// Student comment: Receiver mode - handle HTTP GET status requests
void handle_receiver_status(int client_fd) {
    char response[MAX_BUFFER_SIZE];
    
    if (global_result.is_valid) {
        snprintf(response, sizeof(response),
                 "{\"result\":\"%s\",\"hash\":\"%s\",\"message\":\"%s\"}",
                 global_result.result, global_result.hash, global_result.message);
    } else {
        snprintf(response, sizeof(response),
                 "{\"result\":\"No data received yet\"}");
    }
    
    send_http_response(client_fd, "200 OK", "application/json", response);
}

// Student comment: HTTP server thread function
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
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(HTTP_PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("HTTP bind failed");
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("HTTP listen failed");
        close(server_fd);
        return NULL;
    }
    
    printf("[HTTP] Server listening on port %d (mode: %s)\n", 
           HTTP_PORT, mode == 1 ? "SENDER" : "RECEIVER");
    
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        char buffer[MAX_BUFFER_SIZE] = {0};
        int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            
            // Student comment: Debug: Print received request
            printf("[DEBUG] Received request (mode %d): %.100s...\n", mode, buffer);
            
            // Student comment: Handle CORS preflight requests
            if (strstr(buffer, "OPTIONS /") || strstr(buffer, "OPTIONS /status")) {
                printf("[DEBUG] Handling OPTIONS request\n");
                send_http_response(client_fd, "200 OK", "text/plain", "");
            } else if (mode == 1 && (strstr(buffer, "POST /") || strstr(buffer, "POST / "))) {
                printf("[DEBUG] Handling POST request in sender mode\n");
                // Student comment: Find the JSON body
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
            } else if (mode == 2 && strstr(buffer, "GET /status")) {
                printf("[DEBUG] Handling GET /status request in receiver mode\n");
                handle_receiver_status(client_fd);
            } else if (mode == 1 && strstr(buffer, "GET /status")) {
                printf("[DEBUG] Handling GET /status request in sender mode\n");
                send_http_response(client_fd, "200 OK", "application/json", 
                                  "{\"status\":\"sender_mode\",\"message\":\"Use POST to send messages\"}");
            } else {
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

// Student comment: TCP server thread for receiver mode
void* tcp_server(void* arg) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("TCP socket creation failed");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP bind failed");
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("TCP listen failed");
        close(server_fd);
        return NULL;
    }
    
    printf("[TCP] Receiver listening on port %d\n", TCP_PORT);
    
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        handle_receiver_tcp(client_fd);
    }
    
    close(server_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <sender|receiver>\n", argv[0]);
        printf("Student project: HMAC Voter Authentication System\n");
        return 1;
    }
    
    // Student comment: Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    pthread_t http_thread, tcp_thread;
    int mode = 0;
    
    if (strcmp(argv[1], "sender") == 0) {
        mode = 1;  // Sender mode
        printf("=== STARTING SENDER MODE ===\n");
        printf("Browser should POST to: http://localhost:8080\n");
        printf("Format: {\"message\":\"your_message\",\"secret\":\"shared_secret\"}\n");
        
        if (pthread_create(&http_thread, NULL, http_server, &mode) != 0) {
            perror("Failed to create HTTP thread");
            return 1;
        }
    } else if (strcmp(argv[1], "receiver") == 0) {
        mode = 2;  // Receiver mode
        printf("=== STARTING RECEIVER MODE ===\n");
        printf("Browser should GET: http://localhost:8080/status\n");
        printf("TCP listening on port %d for sender connections\n", TCP_PORT);
        
        if (pthread_create(&http_thread, NULL, http_server, &mode) != 0) {
            perror("Failed to create HTTP thread");
            return 1;
        }
        
        if (pthread_create(&tcp_thread, NULL, tcp_server, NULL) != 0) {
            perror("Failed to create TCP thread");
            return 1;
        }
    } else {
        printf("Invalid mode. Use 'sender' or 'receiver'\n");
        return 1;
    }
    
    // Student comment: Keep main thread alive
    pthread_join(http_thread, NULL);
    if (mode == 2) {
        pthread_join(tcp_thread, NULL);
    }
    
    // Student comment: Cleanup OpenSSL
    EVP_cleanup();
    
    return 0;
}