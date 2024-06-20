#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <tls.h>

/* NOTE =========================================================================================================
Steps to Ensure Proper Certificate Verification
1) Create a CA Certificate and Key:
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes

2) Generate the Server’s Private Key and CSR:
openssl req -newkey rsa:4096 -keyout server-key.pem -out server-req.pem -nodes

3) Sign the Server’s CSR with the CA Certificate:
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365

4) Generate the Client’s Private Key and CSR:
openssl req -newkey rsa:4096 -keyout client-key.pem -out client-req.pem -nodes

5) Sign the Client’s CSR with the CA Certificate:
openssl x509 -req -in client-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365

6) Verify the Certificates:
Ensure that the CA certificate can validate both the server and client certificates:
openssl verify -CAfile ca-cert.pem server-cert.pem
openssl verify -CAfile ca-cert.pem client-cert.pem

7)Run OpenSSL s_server:
openssl s_server -cert server-cert.pem -key server-key.pem -CAfile ca-cert.pem -Verify 1 -accept 4443

8) Run OpenSSL s_client:
openssl s_client -cert client-cert.pem -key client-key.pem -CAfile ca-cert.pem -connect 127.0.0.1:4443

9) encryption of AES-256-CBC
openssl enc -aes-256-cbc -salt -in client-key.pem  -out client-key.pem.enc -k 11112222    
openssl enc -d -aes-256-cbc -in client-key.pem.enc -out client-key.pem.dec -k 11112222 
==============================================================================================================*/

// Buffer size for reading file
#define BUFFER_SIZE 4096

void tls_init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();    
}

void tls_handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    //abort();
}

void tls_new_set_fd(st_tls* p_this, const int sock)
{
    p_this->ssl = SSL_new(p_this->ctx);
    SSL_set_fd(p_this->ssl, sock);
}

void tls_cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* tls_create_context(st_tls* p_this) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (p_this != NULL)
        p_this->ctx = ctx;
    return ctx;
}

void tls_configure_context_file(SSL_CTX *ctx, const char* sz_cert, const char* sz_key, const char* sz_ca_cert) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the certificate and key
    if (SSL_CTX_use_certificate_file(ctx, sz_cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, sz_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the CA certificate to verify server
    if (SSL_CTX_load_verify_locations(ctx, sz_ca_cert, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

void tls_configure_context(st_tls* p_this, const unsigned char* cert, const unsigned char* key, const char* sz_ca_cert) {
    SSL_CTX_set_ecdh_auto(p_this->ctx, 1);

    // Load server's certificate and private key from memory
    BIO *cert_bio = BIO_new_mem_buf((void*)cert, -1);
    BIO *key_bio = BIO_new_mem_buf((void*)key, -1);

    X509 *certificate = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);

    if (SSL_CTX_use_certificate(p_this->ctx, certificate) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey(p_this->ctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the CA certificate to verify server
    if (SSL_CTX_load_verify_locations(p_this->ctx, sz_ca_cert, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require server certificate verification
    SSL_CTX_set_verify(p_this->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(p_this->ctx, 4);

    X509_free(certificate);
    EVP_PKEY_free(pkey);
    BIO_free(cert_bio);
    BIO_free(key_bio);
}


// Function to decrypt the file
/*
openssl enc -aes-256-cbc -salt -in client-key.pem  -out client-key.pem.enc -k 11112222    
openssl enc -d -aes-256-cbc -in client-key.pem.enc -out client-key.pem.dec -k 11112222 
*/
unsigned char* tls_alloc_decrypt_file(const char *input_file, const char *password, int *decrypted_len) {
    FILE *ifp = fopen(input_file, "rb");
    if (!ifp) {
        perror("File opening failed");
        return NULL;
    }

    unsigned char salt[8];
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    // Read the magic text and salt from the file
    unsigned char magic[8];
    if (fread(magic, 1, 8, ifp) != 8 || strncmp((const char *)magic, "Salted__", 8) != 0) {
        fprintf(stderr, "No salt header found in the file\n");
        fclose(ifp);
        return NULL;/*EXIT_FAILURE*/
    }

    if (fread(salt, 1, 8, ifp) != 8) {
        fprintf(stderr, "Failed to read salt\n");
        fclose(ifp);
        return NULL;/*EXIT_FAILURE*/
    }

    // Output the salt
    printf("Salt: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", salt[i]);
    printf("\n");

    // Derive the key and IV
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const EVP_MD *dgst = EVP_sha256();

    if (!EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        tls_handleErrors();
        return NULL;
    }

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

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        tls_handleErrors();
        return NULL;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        tls_handleErrors();
        return NULL;
    }

    unsigned char inbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char *outbuf = NULL;
    int outbuf_len = 0;
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, ifp)) > 0) {
        outbuf = (unsigned char*)realloc(outbuf, outbuf_len + inlen + EVP_MAX_BLOCK_LENGTH);
        if (!outbuf) {
            perror("Memory allocation failed");
            return NULL;
        }

        if (1 != EVP_DecryptUpdate(ctx, outbuf + outbuf_len, &outlen, inbuf, inlen)) {
            tls_handleErrors();
            return NULL;
        }
        outbuf_len += outlen;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, outbuf + outbuf_len, &outlen)) {
        tls_handleErrors();
        return NULL;
    }
    outbuf_len += outlen;

    EVP_CIPHER_CTX_free(ctx);
    fclose(ifp);

    *decrypted_len = outbuf_len;
    return outbuf;
}


//#define TEST
#if defined(TEST)

#define KEY_ENCRYPTED
#define PORT 4443

int main(int argc, char **argv) {

#if defined(KEY_ENCRYPTED)
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *password = argv[1];
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
    SSL_CTX *ctx;
    SSL *ssl;

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


