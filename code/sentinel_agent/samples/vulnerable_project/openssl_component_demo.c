#include <openssl/ssl.h>
#include <openssl/crypto.h>

void init_openssl_demo() {
    SSL_library_init();
}
