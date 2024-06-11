#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void init_openssl() { 
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// usage ssl_client <HOST> <PORT>
// compile with:
// gcc -Wall -I /usr/include/openssl -o ssl_client ssl_client.c -l ssl -l crypto

int main(int argc, char **argv) {
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;
    struct sockaddr_in server_addr;
    char buf[1024];
    int bytes;
    int count = 0;
    srand(time(NULL));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *hostname = argv[1];
    int port = atoi(argv[2]);

    init_openssl();
    ctx = create_context();

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new() failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect() failed\n");
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    } else {
        printf("SSL connection using %s\n", SSL_get_cipher(ssl));

        while (1) {
            sleep(1);
            int secret = rand() % (1024 * 1024 * 1024);
            sprintf(buf, "Client random number %d is %d", count, secret);
            SSL_write(ssl, buf, strlen(buf));

            bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (bytes <= 0) {
                fprintf(stderr, "SSL_read() failed\n");
                ERR_print_errors_fp(stderr);
                break;
            }
            buf[bytes] = 0;
            printf("Received: %s\n", buf);

            count++;
        }
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}