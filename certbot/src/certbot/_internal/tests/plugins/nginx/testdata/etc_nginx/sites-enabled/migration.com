server {
    server_name migration.com;
    server_name summer.com;
}
   
server {
    listen       443 ssl;
    server_name  migration.com;
    server_name  geese.com;

    ssl_certificate      cert.pem;
    ssl_certificate_key  cert.key;

    ssl_session_cache    shared:SSL:1m;
    ssl_session_timeout  5m;

    ssl_ciphers  HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers  on;
}
