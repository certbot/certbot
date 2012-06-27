%module sni_support
%{
  #include <openssl/ssl.h>
  #include <openssl/x509v3.h>
  #include "sni_support.h"
%}

%typemap(out) binary_data_t {
    $result = PyString_FromStringAndSize($1.data,$1.size);
}

%include "sni_support.h"

