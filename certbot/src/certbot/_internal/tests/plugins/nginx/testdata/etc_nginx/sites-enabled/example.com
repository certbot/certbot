server {
    listen       69.50.225.155:9000;
    listen       127.0.0.1;
    server_name .example.com;
    server_name example.*;
}
