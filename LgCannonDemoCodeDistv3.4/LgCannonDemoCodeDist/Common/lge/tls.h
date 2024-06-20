#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

void tls_init_openssl(void);
void tls_handleErrors(void);
void tls_cleanup_openssl(void);
SSL_CTX* tls_create_context(void);
void tls_configure_context_file(SSL_CTX *ctx, const char* sz_cert, const char* sz_key, const char* sz_ca_cert);
void tls_configure_context(SSL_CTX *ctx, const char *cert, const char *key, const char* sz_ca_cert);
unsigned char* tls_alloc_decrypt_file(const char *input_file, const char *password, int *decrypted_len);

#ifdef __cplusplus
} /*extern "C" {*/
#endif




