#include <stdio.h>

#define TEST

#if defined(TEST)

#define KEY_ENCRYPTED
#define PORT 4443

int main(int argc, char** argv) {

#if defined(KEY_ENCRYPTED)
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* password = argv[1];
    char* cert = NULL;
    char* key = NULL;

    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int cert_len = 0;
    cert = tls_alloc_decrypt_file("client-cert.pem.enc", password, &cert_len);
    if (cert == NULL) {
        fprintf(stderr, "Decryption failed.1\n");
        exit(EXIT_FAILURE);
    }
    cert[cert_len] = 0;

    int key_len = 0;
    key = tls_alloc_decrypt_file("client-key.pem.enc", password, &key_len);
    if (cert == NULL) {
        fprintf(stderr, "Decryption failed.2\n");
        exit(EXIT_FAILURE);
    }
    key[key_len] = 0;
#endif /*defined(KEY_ENCRYPTED)*/    
    int sock;
    struct sockaddr_in addr;
    SSL_CTX* ctx;
    SSL* ssl;

    tls_init_openssl();
    ctx = tls_create_context();
#if defined(KEY_ENCRYPTED)    
    tls_configure_context(ctx, cert, key, "ca-cert.pem");
#else /*defined(KEY_ENCRYPTED)*/
    tls_configure_context_file(ctx);
#endif /*defined(KEY_ENCRYPTED)*/

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    else {
        SSL_write(ssl, "hello", strlen("hello"));
        char buf[256] = { 0 };
        SSL_read(ssl, buf, sizeof(buf));
        printf("Received: %s\n", buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    tls_cleanup_openssl();

#if defined(KEY_ENCRYPTED)        
    if (cert != NULL)
        free(cert);
    if (key != NULL)
        free(key);
#endif /*defined(KEY_ENCRYPTED)*/        
    return 0;
}

#endif /*#if defined(TEST)*/
