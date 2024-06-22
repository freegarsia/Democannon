#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

void tls_init_openssl(void);
void tls_handleErrors(void);
void tls_new_set_fd(st_tls* p_this, const int sock);
void tls_cleanup_openssl(st_tls* p_this);
SSL_CTX* tls_create_context(st_tls* p_this, const bool is_for_server);
void tls_configure_context_file(SSL_CTX *ctx, const bool is_for_server, const char* sz_cert, const char* sz_key, const char* sz_ca_cert);
void tls_configure_context(st_tls* p_this, const bool is_for_server, const unsigned char* cert, const unsigned char* key, const char* sz_ca_cert);
unsigned char* tls_alloc_decrypt_file(const char *input_file, const char *password, int *decrypted_len);

#endif /*TLS_H_*/

#ifdef __cplusplus
} /*extern "C" {*/
#endif




