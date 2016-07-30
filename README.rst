.. This file contains of a series of comments that are used to include sections of this README in other files. Do not modify these comments unless you know what you are doing. tag:intro-begin

Certbot is part of EFF’s effort to encrypt the entire Internet. Secure communication over the Web relies on HTTPS, which requires the use of a digital certificate that lets browsers verify the identify of web servers (e.g., is that really google.com?). Web servers obtain their certificates from trusted third parties called certificate authorities (CAs). Certbot is an easy-to-use client that fetches a certificate from Let’s Encrypt—an open certificate authority launched by the EFF, Mozilla, and others—and deploys it to a web server.

Anyone who has gone through the trouble of setting up a secure website knows what a hassle getting and maintaining a certificate is. Certbot and Let’s Encrypt can automate away the pain and let you turn on and manage HTTPS with simple commands. Using Certbot and Let's Encrypt is free, so there’s no need to arrange payment.

How you use Certbot depends on the configuration of your web server. The best way to get started is to use our `interactive guide <https://certbot.eff.org>`_. It generates instructions based on your configuration settings. In most cases, you’ll need `root or administrator access <https://certbot.eff.org/faq/#does-certbot-require-root-privileges>`_ to your web server to run Certbot.

If you’re using a hosted service and don’t have direct access to your web server, you might not be able to use Certbot. Check with your hosting provider for documentation about uploading certificates or using certificates issues by Let’s Encrypt.

.. Do not modify this comment unless you know what you're doing. tag:intro-end

.. Do not modify this comment unless you know what you're doing. tag:features-begin

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

.. Do not modify this comment unless you know what you're doing. tag:features-end

For extensive documentation on using and contributing to Certbot, go to https://certbot.eff.org/docs. If you would like to contribute to the project or run the latest code from git, you should read our `developer guide <https://certbot.eff.org/docs/contributing.html>`_.
