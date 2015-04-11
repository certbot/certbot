server {
    listen       9000;
    server_name .example.com;
    server_name example.*;
}
