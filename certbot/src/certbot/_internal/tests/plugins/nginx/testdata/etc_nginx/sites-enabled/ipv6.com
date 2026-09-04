server {
    listen 80;
    listen [::]:80;
    server_name ipv6.com;
}
