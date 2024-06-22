#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define KEY_ENCRYPTED

#define PORT 4443

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

void configure_context_file(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the CA certificate to verify server
    if (SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

void configure_context(SSL_CTX *ctx, const char *cert, const char *key) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Load server's certificate and private key from memory
    BIO *cert_bio = BIO_new_mem_buf((void*)cert, -1);
    BIO *key_bio = BIO_new_mem_buf((void*)key, -1);

    X509 *certificate = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);

    if (SSL_CTX_use_certificate(ctx, certificate) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the CA certificate to verify server
    if (SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    X509_free(certificate);
    EVP_PKEY_free(pkey);
    BIO_free(cert_bio);
    BIO_free(key_bio);
}


#if 0
int decrypt_file(const char *input_file, char **output, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Unable to open file");
        return 0;
    }

    fseek(in, 0, SEEK_END);
    long inlen = ftell(in);
    fseek(in, 0, SEEK_SET);

    unsigned char *indata = malloc(inlen);
    fread(indata, 1, inlen, in);
    fclose(in);

    unsigned char key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, (unsigned char *)password, strlen(password), 1, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char *outdata = malloc(inlen);
    int outlen, tmplen;
    EVP_DecryptUpdate(ctx, outdata, &outlen, indata, inlen);
    EVP_DecryptFinal_ex(ctx, outdata + outlen, &tmplen);
    outlen += tmplen;

    outdata[outlen] = '\0';
    *output = (char *)outdata;

    EVP_CIPHER_CTX_free(ctx);
    free(indata);

    return 1;
}
#endif

// Buffer size for reading file
#define BUFFER_SIZE 4096

// Function to handle errors
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to decrypt the file
unsigned char *decrypt_file(const char *input_file, const char *password, int *decrypted_len) {
    FILE *ifp = fopen(input_file, "rb");
    if (!ifp) {
        perror("File opening failed");
        return NULL;
    }

    #if 0
    // Read the salt from the beginning of the input file
    unsigned char salt[8];
    if (fread(salt, 1, 8, ifp) != 8) {
        perror("Reading salt failed");
        return NULL;
    }

    // Derive the key and IV from the password and salt
    unsigned char key[32], iv[32];
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        handleErrors();
    }
    #else
    unsigned char salt[8];
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    // Read the magic text and salt from the file
    unsigned char magic[8];
    if (fread(magic, 1, 8, ifp) != 8 || strncmp((const char *)magic, "Salted__", 8) != 0) {
        fprintf(stderr, "No salt header found in the file\n");
        fclose(ifp);
        return EXIT_FAILURE;
    }

    if (fread(salt, 1, 8, ifp) != 8) {
        fprintf(stderr, "Failed to read salt\n");
        fclose(ifp);
        return EXIT_FAILURE;
    }

    // Output the salt
    printf("Salt: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", salt[i]);
    printf("\n");

    // Derive the key and IV
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const EVP_MD *dgst = EVP_sha256();

    if (!EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)password, strlen(password), 1, key, iv))
        handleErrors();

    // Output the key
    printf("Key: ");
    for (int i = 0; i < EVP_CIPHER_key_length(cipher); i++)
        printf("%02x", key[i]);
    printf("\n");

    // Output the IV
    printf("IV: ");
    for (int i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
        printf("%02x", iv[i]);
    printf("\n");

    #endif

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    unsigned char inbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char *outbuf = NULL;
    int outbuf_len = 0;
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, ifp)) > 0) {
        outbuf = realloc(outbuf, outbuf_len + inlen + EVP_MAX_BLOCK_LENGTH);
        if (!outbuf) {
            perror("Memory allocation failed");
            return NULL;
        }

        if (1 != EVP_DecryptUpdate(ctx, outbuf + outbuf_len, &outlen, inbuf, inlen)) {
            handleErrors();
        }
        outbuf_len += outlen;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, outbuf + outbuf_len, &outlen)) {
        handleErrors();
    }
    outbuf_len += outlen;

    EVP_CIPHER_CTX_free(ctx);
    fclose(ifp);

    *decrypted_len = outbuf_len;
    return outbuf;
}



int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *password = argv[1];
    char* cert = NULL;
    char* key = NULL;

#if defined(KEY_ENCRYPTED)
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int cert_len = 0;
    cert = decrypt_file("client-cert.pem.enc", password, &cert_len);
    if (cert == NULL) {
        fprintf(stderr, "Decryption failed.1\n");
        exit(EXIT_FAILURE);    
    }
    cert[cert_len] = 0;
    
    int key_len = 0;
    key = decrypt_file("client-key.pem.enc", password, &key_len);
    if (cert == NULL) {
        fprintf(stderr, "Decryption failed.2\n");
        exit(EXIT_FAILURE);   
    }    
    key[key_len] = 0;
#if 0
    if (!decrypt_file("client-cert.pem.enc", &cert, password) || !decrypt_file("client-key.pem.enc", &key, password)) {
        fprintf(stderr, "Decryption failed\n");
        exit(EXIT_FAILURE);
    }
#endif    
#endif    
    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();
    ctx = create_context();
#if defined(KEY_ENCRYPTED)    
    configure_context(ctx, cert, key);
#else
    configure_context_file(ctx);
#endif

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
    } else {
        SSL_write(ssl, "hello", strlen("hello"));
        char buf[256] = {0};
        SSL_read(ssl, buf, sizeof(buf));
        printf("Received: %s\n", buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    if (cert != NULL)
        free(cert);
    if (key != NULL)
        free(key);    
    return 0;
}

