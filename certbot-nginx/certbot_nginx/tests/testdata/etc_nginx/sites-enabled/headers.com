server {
    server_name headers.com;
    add_header X-Content-Type-Options nosniff;
}
