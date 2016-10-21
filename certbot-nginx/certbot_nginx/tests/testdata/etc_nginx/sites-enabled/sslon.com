server {
	server_name sslon.com;
	ssl on;
	ssl_certificate snakeoil.cert;
	ssl_certificate_key snakeoil.key;
}
