#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void tls_init_openssl();
void tls_handleErrors(void);
void tls_cleanup_openssl();
SSL_CTX* tls_create_context();





