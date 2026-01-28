/*
 * Geminium - Lightweight Gemini Protocol Server
 * Copyright (C) 2026 Unionium NCO
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Source: https://github.com/Unionium/geminium
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define PORT 1965
#define BUFFER_SIZE 1024
#define MAX_RESPONSE_SIZE 8192

int main() {
    SSL_CTX* ssl_ctx;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN];
    FILE* log_file;

    // Open log file
    log_file = fopen("log.txt", "a");
    if (!log_file) {
        perror("Cannot open log file");
        exit(EXIT_FAILURE);
    }

    // Get current time for log
    time_t now;
    struct tm *timeinfo;
    char timestamp[20];

    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    fprintf(log_file, "=== Server started at %s ===\n", timestamp);
    fflush(log_file);

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "./server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "./server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Certificate and private key do not match\n");
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_fd);
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    printf("Gemini server running on port %d\n", PORT);
    printf("Logging to log.txt\n");
    printf("Powered by Geminium\n");

    while (1) {
        // Accept connection
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        // Get client IP address
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        // Create SSL connection
        SSL* ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            // Log SSL error
            fprintf(log_file, "%s: SSL handshake failed\n", client_ip);
            fflush(log_file);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // Read request
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, BUFFER_SIZE - 1);

        // Remove \r\n at the end
        buffer[strcspn(buffer, "\r\n")] = 0;

        // Parse path from URL
        char* path = buffer;
        char* gemini_proto = strstr(buffer, "gemini://");
        if (gemini_proto) {
            path = gemini_proto + 9; // Skip "gemini://"
            char* host_end = strchr(path, '/');
            if (host_end) {
                path = host_end;
            } else {
                path = "/";
            }
        } else {
            // Not a valid Gemini URL
            path = "/";
        }

        char* status_code = "20";
        char* mime_type = "text/gemini";
        char response[MAX_RESPONSE_SIZE];
        memset(response, 0, MAX_RESPONSE_SIZE);

        if (strcmp(path, "/") == 0) {
            // Serve index.gemini
            FILE* file = fopen("./index.gemini", "r");
            if (file) {
                char content[BUFFER_SIZE];
                memset(content, 0, BUFFER_SIZE);
                fread(content, 1, BUFFER_SIZE - 1, file);
                fclose(file);
                snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, content);
            } else {
                status_code = "51";
                char* error = "# File index.gemini not found\n\n---\n*Powered by Geminium*";
                snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, error);
            }
        } else if (strstr(path, ".py") != NULL || access(strcat(strdup(path), ".py"), F_OK) == 0) {
            // Execute Python script
            char command[BUFFER_SIZE];
            char script_path[BUFFER_SIZE];

            // Handle .py extension
            if (strlen(path) > 3 && strcmp(path + strlen(path) - 3, ".py") == 0) {
                snprintf(script_path, sizeof(script_path), ".%s", path);
            } else {
                snprintf(script_path, sizeof(script_path), ".%s.py", path);
            }

            // Check if script exists
            if (access(script_path, F_OK) != 0) {
                status_code = "51";
                char* error = "# Script not found\n\n---\n*Powered by Geminium*";
                snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, error);
            } else {
                snprintf(command, sizeof(command), "python3 %s", script_path);

                // Execute command and read output
                FILE* pipe = popen(command, "r");
                if (pipe) {
                    char output[MAX_RESPONSE_SIZE];
                    memset(output, 0, MAX_RESPONSE_SIZE);
                    size_t bytes_read = fread(output, 1, MAX_RESPONSE_SIZE - 1, pipe);
                    pclose(pipe);
                    output[bytes_read] = '\0';
                    snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, output);
                } else {
                    status_code = "42";
                    char* error = "# Script execution error\n\n---\n*Powered by Geminium*";
                    snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, error);
                }
            }
        } else {
            // Try to serve static .gemini file
            char file_path[BUFFER_SIZE];
            snprintf(file_path, sizeof(file_path), ".%s.gemini", path);

            FILE* file = fopen(file_path, "r");
            if (file) {
                char content[MAX_RESPONSE_SIZE];
                memset(content, 0, MAX_RESPONSE_SIZE);
                size_t bytes_read = fread(content, 1, MAX_RESPONSE_SIZE - 1, file);
                fclose(file);
                content[bytes_read] = '\0';
                snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, content);
            } else {
                status_code = "51";
                char* error = "# Not found\n\n---\n*Powered by Geminium*";
                snprintf(response, sizeof(response), "%s %s\r\n%s", status_code, mime_type, error);
            }
        }

        // Send response
        SSL_write(ssl, response, strlen(response));

        // Log the request
        time(&now);
        timeinfo = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

        fprintf(log_file, "[%s] %s: %s: %s\n",
                timestamp, client_ip, path, status_code);
        fflush(log_file);

        // Cleanup
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    // Cleanup (never reached in this example)
    SSL_CTX_free(ssl_ctx);
    close(server_fd);
    fclose(log_file);

    return 0;
}
