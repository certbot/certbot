:orphan:

..
   CERTBOT_DOCS causes Certbot's help output to be more generic and setting
   COLUMNS prevents the size of the terminal Certbot is running in while
   building the docs from influncing the formatting.
.. program-output:: CERTBOT_DOCS=1 COLUMNS=80 certbot --help all
   :shell:
