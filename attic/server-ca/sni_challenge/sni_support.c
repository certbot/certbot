#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include "sni_support.h"

void set_sni_ext(SSL *ctx, char *servername) {
  SSL_set_tlsext_host_name(ctx, servername);
}

int get_nid(X509_EXTENSION *ext) {
  return OBJ_obj2nid(X509_EXTENSION_get_object(ext));
}

binary_data_t get_unknown_value(X509_EXTENSION *ext) {
  binary_data_t result;
  result.size = ext->value->length;
  result.data = (unsigned char *)ext->value->data;
  return result;
} 
