=====================
Current Features
=====================

* Supports multiple web servers:

  - apache/2.x (working on Debian 8+ and Ubuntu 12.04+)
  - standalone (runs its own simple webserver to prove you control a domain)
  - webroot (adds files to webroot directories in order to prove control of
    domains and obtain certs)
  - nginx/0.8.48+ (highly experimental, not included in certbot-auto)

* The private key is generated locally on your system.
* Can talk to the Let's Encrypt CA or optionally to other ACME
  compliant services.
* Can get domain-validated (DV) certificates.
* Can revoke certificates.
* Adjustable RSA key bit-length (2048 (default), 4096, ...).
* Can optionally install a http -> https redirect, so your site effectively
  runs https only (Apache only)
* Fully automated.
* Configuration changes are logged and can be reverted.
* Supports ncurses and text (-t) UI, or can be driven entirely from the
  command line.
* Free and Open Source Software, made with Python.