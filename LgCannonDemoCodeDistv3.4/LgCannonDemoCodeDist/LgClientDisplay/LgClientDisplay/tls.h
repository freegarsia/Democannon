#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifndef TLS_H_
#define TLS_H_

struct st_tls {
    SSL_CTX* ctx;
    SSL* ssl;
};
typedef struct st_tls st_tls;

struct st_aes
{
    unsigned char salt[8];
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
};
typedef struct st_aes st_aes;


void tls_init_openssl(void);
void tls_handleErrors(void);
void tls_new_set_fd(st_tls* p_this, const int sock);
void tls_cleanup_openssl();
SSL_CTX* tls_create_context();
void tls_configure_context_file(SSL_CTX *ctx, const char* sz_cert, const char* sz_key, const char* sz_ca_cert);
void tls_configure_context(SSL_CTX* ctx, const unsigned char* cert, const unsigned char* key, const char* sz_ca_cert);
unsigned char* tls_alloc_decrypt_file(const char *input_file, const char *password, int *decrypted_len);
void encrypt_and_save(unsigned char* data, int data_len, const char* outputFilename, unsigned char* key, unsigned char* iv);
void writeFile(const char* filename, unsigned char* data, int data_len);
int aes_get_key_iv_of_password(st_aes* p_this, const char* sz_password);
int aes_encrypt_to_file(st_aes* p_this, const unsigned char* plaintext, const int plaintext_len, const char* sz_file_name);
unsigned char* aes_encrypt_to_alloc(st_aes* p_this, const unsigned char* plaintext, const int plaintext_len, int* p_ciphertext_len);
void aes_handleErrors(void);

#if !defined(LOG_ENABLE)
#ifndef PRINTF_EMPTY
#define PRINTF_EMPTY

static void printf_empty(const char* format, ...) {};
#define printf printf_empty

#endif /* PRINTF_EMPTY */
#endif /* LOG_ENABLE */

#endif /*TLS_H_*/

#ifdef __cplusplus
} /*extern "C" {*/
#endif




