#ifndef SNI_SUPPORT_H
#define SNI_SUPPORT_H

typedef struct binary_data {
  int size;
  unsigned char* data;
} binary_data_t;

void set_sni_ext(SSL *ctx, char *servername);
int get_nid(X509_EXTENSION *ext);
binary_data_t get_unknown_value(X509_EXTENSION *ext);

#endif
