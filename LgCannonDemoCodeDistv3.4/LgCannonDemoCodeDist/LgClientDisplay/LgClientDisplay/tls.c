#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls.h"

/* NOTE =========================================================================================================
Steps to Ensure Proper Certificate Verification
1) Create a CA Certificate and Key:
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes

2) Generate the Server뭩 Private Key and CSR:
openssl req -newkey rsa:4096 -keyout server-key.pem -out server-req.pem -nodes

3) Sign the Server뭩 CSR with the CA Certificate:
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365

4) Generate the Client뭩 Private Key and CSR:
openssl req -newkey rsa:4096 -keyout client-key.pem -out client-req.pem -nodes

5) Sign the Client뭩 CSR with the CA Certificate:
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


void tls_cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* tls_create_context() {
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

void tls_configure_context(SSL_CTX *ctx, const char *cert, const char *key, const char* sz_ca_cert) {
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
    if (SSL_CTX_load_verify_locations(ctx, sz_ca_cert, NULL) <= 0) {
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


// Function to decrypt the file
/*
openssl enc -aes-256-cbc -salt -in client-key.pem  -out client-key.pem.enc -k 11112222    
openssl enc -d -aes-256-cbc -in client-key.pem.enc -out client-key.pem.dec -k 11112222 
*/
unsigned char* tls_alloc_decrypt_file(const char *input_file, const char *password, int *decrypted_len) {
    FILE* ifp;
    errno_t err = fopen_s(&ifp, input_file, "rb"); 
    
    if (err != 0) {
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

void encrypt_and_save(unsigned char* data, int data_len, const char* outputFilename, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx;
    int len, ciphertext_len;
    unsigned char* ciphertext;
    int block_size;

    // 암호화 설정
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        tls_handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        tls_handleErrors();
    }

    // 암호화 수행
    block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    ciphertext = malloc(data_len + block_size);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Failed to allocate memory.\n");
        abort();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        tls_handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        tls_handleErrors();
    }
    ciphertext_len += len;

    // 암호화된 데이터를 출력 파일에 쓰기
    writeFile(outputFilename, ciphertext, ciphertext_len);

    // 정리
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
}

void writeFile(const char* filename, unsigned char* data, int data_len) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Failed to open file : %s\n", filename);
        abort();
    }
    fwrite(data, 1, data_len, file);
    fclose(file);
}

int aes_get_key_iv_of_password(st_aes* p_this, const char* sz_password)
{
    // Derive the key and IV
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const EVP_MD* dgst = EVP_sha256();

    if (!EVP_BytesToKey(cipher, dgst, p_this->salt, (unsigned char*)sz_password, strlen(sz_password), 1, p_this->key, p_this->iv)) {
        tls_handleErrors();
        return -1;
    }

    // Output the key
    printf("Key: ");
    for (int i = 0; i < EVP_CIPHER_key_length(cipher); i++)
        printf("%02x", p_this->key[i]);
    printf("\n");

    // Output the IV
    printf("IV: ");
    for (int i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
        printf("%02x", p_this->iv[i]);
    printf("\n");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        tls_handleErrors();
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, p_this->key, p_this->iv)) {
        tls_handleErrors();
        return -1;
    }
    return 0;
}

int aes_encrypt_to_file(st_aes* p_this, const unsigned char* plaintext, const int plaintext_len, const char* sz_file_name)
{
    int ciphertext_len = 0;
    unsigned char* ciphertext = aes_encrypt_to_alloc(p_this, plaintext, plaintext_len, &ciphertext_len);
    if (ciphertext == NULL || ciphertext_len == 0) {
        return -1;
    }

    FILE* ifp = fopen(sz_file_name, "wb");
    if (!ifp) {
        perror("File opening failed");
        return -1;
    }
    // Write salt and encrypted data to file
    const char sz_salt_magic[] = "Salted__";
    fwrite(sz_salt_magic, 1, sizeof(sz_salt_magic) - 1, ifp);
    fwrite(p_this->salt, 1, sizeof(p_this->salt), ifp);
    fwrite(ciphertext, 1, ciphertext_len, ifp);
    free(ciphertext);
    return 0;
}

unsigned char* aes_encrypt_to_alloc(st_aes* p_this, const unsigned char* plaintext, const int plaintext_len, int* p_ciphertext_len)
{
    EVP_CIPHER_CTX* ctx;
    int len, ciphertext_len;

    // Allocate memory for ciphertext
    int ciphertext_max_len = plaintext_len + EVP_MAX_BLOCK_LENGTH;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_max_len);
    if (!ciphertext) {
        perror("Unable to allocate memory for ciphertext");
        abort();
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) aes_handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, p_this->key, p_this->iv))
        aes_handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        aes_handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        aes_handleErrors();
    ciphertext_len += len;

    *p_ciphertext_len = ciphertext_len;
    return ciphertext;
}

void aes_handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    //abort();
}
