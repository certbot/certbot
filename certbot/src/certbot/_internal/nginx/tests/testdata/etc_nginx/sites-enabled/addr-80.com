server {
    listen 1.2.3.4:80;
    listen [1:20::300]:80;
    server_name addr-80.com;
}
