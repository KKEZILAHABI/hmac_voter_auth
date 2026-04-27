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
#define SENDER_HTTP_PORT 8080
#define RECEIVER_HTTP_PORT 8081
#define TCP_PORT 9090

// MODIFIED: Replaced AuthResult with a PayloadBuffer to hold incoming data without verifying
typedef struct {
    char message[MAX_BUFFER_SIZE];  
    char hash[65];        
    int has_data;        
} PayloadBuffer;

typedef struct {
    char secret[256];    
    int is_set;          
} SecretStorage;

PayloadBuffer global_buffer = {0};  
SecretStorage global_secret = {0};  

void compute_sha256(const char *data, int data_len, unsigned char *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    
    EVP_MD_CTX_free(mdctx);
}

void hash_to_hex(const unsigned char *hash, char *hex_string) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[64] = '\0';
}

void send_http_response(int client_fd, const char *status_code, const char *content_type, const char *body) {
    char headers[1024];
    snprintf(headers, sizeof(headers), 
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type\r\n"
             "\r\n",
             status_code, content_type, strlen(body));
             
    send(client_fd, headers, strlen(headers), 0);
    send(client_fd, body, strlen(body), 0);
}

void serve_index_html(int client_fd) {
    FILE *file = fopen("index.html", "r");
    if (!file) {
        send_http_response(client_fd, "404 Not Found", "text/html", 
                          "<html><body><h1>404 - index.html not found</h1></body></html>");
        return;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
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

int parse_json_body(const char *body, char *message, char *message2, char *secret, char *receiver_ip) {
    char *msg_start = strstr(body, "\"message\":\"");
    char *msg2_start = strstr(body, "\"message2\":\"");
    char *secret_start = strstr(body, "\"secret\":\"");
    char *ip_start = strstr(body, "\"receiver_ip\":\"");
    
    if (!msg_start || !msg2_start || !secret_start || !ip_start) return 0;
    
    msg_start += 11;  
    msg2_start += 12; 
    secret_start += 10; 
    ip_start += 15;    
    
    char *msg_end = strstr(msg_start, "\"");
    char *msg2_end = strstr(msg2_start, "\"");
    char *secret_end = strstr(secret_start, "\"");
    char *ip_end = strstr(ip_start, "\"");
    
    if (!msg_end || !msg2_end || !secret_end || !ip_end) return 0;
    
    int msg_len = msg_end - msg_start;
    int msg2_len = msg2_end - msg2_start;
    int secret_len = secret_end - secret_start;
    int ip_len = ip_end - ip_start;
    
    strncpy(message, msg_start, msg_len);
    message[msg_len] = '\0';
    
    strncpy(message2, msg2_start, msg2_len);
    message2[msg2_len] = '\0';
    
    strncpy(secret, secret_start, secret_len);
    secret[secret_len] = '\0';
    
    strncpy(receiver_ip, ip_start, ip_len);
    receiver_ip[ip_len] = '\0';
    
    return 1;
}

int parse_secret_body(const char *body, char *secret) {
    char *secret_start = strstr(body, "\"secret\":\"");
    if (!secret_start) return 0;
    
    secret_start += 10; 
    char *secret_end = strstr(secret_start, "\"");
    if (!secret_end) return 0;
    
    int secret_len = secret_end - secret_start;
    strncpy(secret, secret_start, secret_len);
    secret[secret_len] = '\0';
    return 1;
}

void handle_sender_post(int client_fd, const char *body) {
    char message[MAX_BUFFER_SIZE] = {0};
    char message2[MAX_BUFFER_SIZE] = {0}; 
    char secret[256] = {0};
    char receiver_ip[64] = {0};
    
    if (!parse_json_body(body, message, message2, secret, receiver_ip)) {
        send_http_response(client_fd, "400 Bad Request", "application/json", 
                          "{\"error\":\"Invalid JSON format - need message, message2, secret, and receiver_ip\"}");
        return;
    }
    
    char combined[MAX_BUFFER_SIZE + 256];
    snprintf(combined, sizeof(combined), "%s%s", message, secret);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(combined, strlen(combined), hash);
    
    char hex_hash[65];
    hash_to_hex(hash, hex_hash);
    
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
    
    if (connect(tcp_socket, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr)) < 0) {
        close(tcp_socket);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "{\"error\":\"Could not connect to receiver at %s\"}", receiver_ip);
        send_http_response(client_fd, "500 Internal Server Error", "application/json", error_msg);
        return;
    }
    
    char tcp_message[MAX_BUFFER_SIZE + 65];
    snprintf(tcp_message, sizeof(tcp_message), "%s|%s", message2, hex_hash);
    send(tcp_socket, tcp_message, strlen(tcp_message), 0);
    close(tcp_socket);
    
    char response[256];
    snprintf(response, sizeof(response), 
             "{\"status\":\"sent\",\"hash\":\"%s\"}", hex_hash);
    send_http_response(client_fd, "200 OK", "application/json", response);
}

void handle_receiver_tcp(int client_fd) {
    char buffer[MAX_BUFFER_SIZE] = {0};
    int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received <= 0) {
        close(client_fd);
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    char *separator = strchr(buffer, '|');
    if (!separator) {
        close(client_fd);
        return;
    }
    
    *separator = '\0';
    char *message = buffer;
    char *received_hash = separator + 1;
    
    // MODIFIED: Buffer the data immediately without verification. 
    strncpy(global_buffer.message, message, MAX_BUFFER_SIZE - 1);
    global_buffer.message[MAX_BUFFER_SIZE - 1] = '\0';
    
    strncpy(global_buffer.hash, received_hash, 64);
    global_buffer.hash[64] = '\0';
    
    global_buffer.has_data = 1;
    
    close(client_fd);
}

void handle_receiver_status(int client_fd) {
    char response[MAX_BUFFER_SIZE * 2];
    
    // MODIFIED: Enforce the salt check, buffer status parsing, and compute hash dynamically
    if (!global_buffer.has_data) {
        snprintf(response, sizeof(response), "{\"status\":\"waiting\"}");
    } else if (!global_secret.is_set) {
        snprintf(response, sizeof(response), "{\"status\":\"needs_salt\"}");
    } else {
        char combined[MAX_BUFFER_SIZE + 256];
        snprintf(combined, sizeof(combined), "%s%s", global_buffer.message, global_secret.secret);
        
        unsigned char computed_hash[SHA256_DIGEST_LENGTH];
        compute_sha256(combined, strlen(combined), computed_hash);
        
        char computed_hex[65];
        hash_to_hex(computed_hash, computed_hex);
        
        int is_match = (strcmp(global_buffer.hash, computed_hex) == 0);
        const char* result_text = is_match ? "Match Valid" : "No Match (MitM Detected)";
        
        snprintf(response, sizeof(response),
                 "{\"status\":\"complete\",\"result\":\"%s\",\"message\":\"%s\",\"received_hash\":\"%s\",\"recalculated_hash\":\"%s\",\"receiver_salt\":\"%s\"}",
                 result_text, global_buffer.message, global_buffer.hash, computed_hex, global_secret.secret);
    }
    
    send_http_response(client_fd, "200 OK", "application/json", response);
}

void handle_get_mode(int client_fd, int mode) {
    char response[MAX_BUFFER_SIZE];
    if (mode == 1) snprintf(response, sizeof(response), "{\"mode\":\"sender\"}");
    else snprintf(response, sizeof(response), "{\"mode\":\"receiver\"}");
    send_http_response(client_fd, "200 OK", "application/json", response);
}

void handle_get_secret(int client_fd) {
    char response[MAX_BUFFER_SIZE];
    if (global_secret.is_set) snprintf(response, sizeof(response), "{\"secret_set\":true}");
    else snprintf(response, sizeof(response), "{\"secret_set\":false}");
    send_http_response(client_fd, "200 OK", "application/json", response);
}

void handle_set_secret(int client_fd, const char *body) {
    char secret[256] = {0};
    if (!parse_secret_body(body, secret)) {
        send_http_response(client_fd, "400 Bad Request", "application/json", 
                          "{\"error\":\"Invalid JSON format - need secret\"}");
        return;
    }
    strncpy(global_secret.secret, secret, sizeof(global_secret.secret) - 1);
    global_secret.secret[sizeof(global_secret.secret) - 1] = '\0';
    global_secret.is_set = 1;
    
    send_http_response(client_fd, "200 OK", "application/json", "{\"status\":\"secret_set\"}");
}

void* http_server(void* arg) {
    int mode = *(int*)arg;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(mode == 1 ? SENDER_HTTP_PORT : RECEIVER_HTTP_PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) return NULL;
    if (listen(server_fd, 5) < 0) return NULL;
    
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        char buffer[MAX_BUFFER_SIZE] = {0};
        int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            
            if (strstr(buffer, "OPTIONS /") || strstr(buffer, "OPTIONS /status") || 
                strstr(buffer, "OPTIONS /send") || strstr(buffer, "OPTIONS /secret") || 
                strstr(buffer, "OPTIONS /set_secret") || strstr(buffer, "OPTIONS /mode")) {
                send_http_response(client_fd, "200 OK", "text/plain", "");
            } 
            else if (strstr(buffer, "GET / HTTP/1.1") || strstr(buffer, "GET / HTTP/1.0")) {
                serve_index_html(client_fd);
            }
            else if (mode == 1 && strstr(buffer, "POST /send")) {
                char *body_start = strstr(buffer, "\r\n\r\n");
                if (body_start) handle_sender_post(client_fd, body_start + 4);
            }
            else if (mode == 2 && strstr(buffer, "GET /status")) {
                handle_receiver_status(client_fd);
            }
            else if (strstr(buffer, "GET /mode")) {
                handle_get_mode(client_fd, mode);
            }
            else if (mode == 2 && strstr(buffer, "GET /secret")) {
                handle_get_secret(client_fd);
            }
            else if (mode == 2 && strstr(buffer, "POST /set_secret")) {
                char *body_start = strstr(buffer, "\r\n\r\n");
                if (body_start) handle_set_secret(client_fd, body_start + 4);
            }
            else {
                send_http_response(client_fd, "404 Not Found", "application/json", 
                                  "{\"error\":\"Endpoint not found\"}");
            }
        }
        close(client_fd);
    }
    close(server_fd);
    return NULL;
}

void* tcp_server(void* arg) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) return NULL;
    if (listen(server_fd, 5) < 0) return NULL;
    
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        handle_receiver_tcp(client_fd);
    }
    close(server_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    
    OpenSSL_add_all_algorithms();
    pthread_t http_thread, tcp_thread;
    int mode = 0;
    
    if (strcmp(argv[1], "sender") == 0) {
        mode = 1;
        printf("Sender node initialized. Launch browser pointing to http://localhost:%d\n", SENDER_HTTP_PORT);
        if (pthread_create(&http_thread, NULL, http_server, &mode) != 0) return 1;
    } 
    else if (strcmp(argv[1], "receiver") == 0) {
        mode = 2;
        printf("Receiver node initialized. Launch browser pointing to http://localhost:%d\n", RECEIVER_HTTP_PORT);
        printf("Receiver mapped to TCP ingestion on port %d\n", TCP_PORT);
        if (pthread_create(&http_thread, NULL, http_server, &mode) != 0) return 1;
        if (pthread_create(&tcp_thread, NULL, tcp_server, NULL) != 0) return 1;
    } 
    else {
        return 1;
    }
    
    pthread_join(http_thread, NULL);
    if (mode == 2) pthread_join(tcp_thread, NULL);
    EVP_cleanup();
    return 0;
}