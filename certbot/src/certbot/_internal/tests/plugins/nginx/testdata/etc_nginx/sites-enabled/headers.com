server {
    server_name headers.com;
    add_header X-Content-Type-Options nosniff;
    ssl on;
    ssl_certificate snakeoil.cert;
    ssl_certificate_key snakeoil.key;
}
