.. This file contains a series of comments that are used to include sections of this README in other files. Do not modify these comments unless you know what you are doing. tag:intro-begin

|build-status|

.. |build-status| image:: https://img.shields.io/azure-devops/build/certbot/ba534f81-a483-4b9b-9b4e-a60bec8fee72/5/main
   :target: https://dev.azure.com/certbot/certbot/_build?definitionId=5
   :alt: Azure Pipelines CI status

.. image:: https://raw.githubusercontent.com/EFForg/design/master/logos/certbot/eff-certbot-lockup.png
  :width: 200
  :alt: EFF Certbot Logo

Certbot is part of EFF's effort to encrypt the entire Internet. Secure communication over the Web relies on HTTPS, which requires the use of a digital certificate that lets browsers verify the identity of web servers (e.g., is that really google.com?). Web servers obtain their certificates from trusted third parties called certificate authorities (CAs). Certbot is an easy-to-use client that fetches a certificate from Let’s Encrypt—an open certificate authority launched by the EFF, Mozilla, or any other ACME CA, and deploys it to a web server.

Anyone who has gone through the trouble of setting up a secure website knows what a hassle getting and maintaining a certificate is. Certbot and Let's Encrypt (or any other ACME CA) can automate away the pain and let you turn on and manage HTTPS with simple commands. Using Certbot and Let's Encrypt as well as some other ACME CAs is free.

.. _installation:

Getting Started
---------------
The best way to get started is to use our `interactive guide <https://certbot.eff.org>`_. It generates instructions based on your configuration settings. In most cases, you’ll need `root or administrator access <https://certbot.eff.org/faq/#does-certbot-require-root-administrator-privileges>`_ to your web server to run Certbot.

Certbot is meant to be run directly on your web server on the command line, not on your personal computer. If you’re using a hosted service and don’t have direct access to your web server, you might not be able to use Certbot. Check with your hosting provider for documentation about uploading certificates or using certificates issued by Let's Encrypt or any other ACME CA.

Contributing
------------

If you'd like to contribute to this project please read `Developer Guide
<https://certbot.eff.org/docs/contributing.html>`_.

This project is governed by `EFF's Public Projects Code of Conduct <https://www.eff.org/pages/eppcode>`_.

Links
=====

.. Do not modify this comment unless you know what you're doing. tag:links-begin

Documentation: https://certbot.eff.org/docs

Software project: https://github.com/certbot/certbot

Changelog: https://github.com/certbot/certbot/blob/main/certbot/CHANGELOG.md

For Contributors: https://certbot.eff.org/docs/contributing.html

For Users: https://certbot.eff.org/docs/using.html

Main Website: https://certbot.eff.org

Let's Encrypt Website: https://letsencrypt.org

Community: https://community.letsencrypt.org

ACME spec: `RFC 8555 <https://tools.ietf.org/html/rfc8555>`_

ACME working area in github (archived): https://github.com/ietf-wg-acme/acme

.. Do not modify this comment unless you know what you're doing. tag:links-end

.. Do not modify this comment unless you know what you're doing. tag:intro-end

.. Do not modify this comment unless you know what you're doing. tag:features-begin

Current Features
=====================

* Supports multiple web servers:

  - Apache 2.4+
  - nginx/0.8.48+
  - webroot (adds files to webroot directories in order to prove control of
    domains and obtain certificates)
  - standalone (runs its own simple webserver to prove you control a domain)
  - other server software via `third party plugins <https://certbot.eff.org/docs/using.html#third-party-plugins>`_

* The private key is generated locally on your system.
* Can talk to the Let's Encrypt CA or optionally to other ACME
  compliant services.
* Can get domain-validated (DV) certificates.
* Can revoke certificates.
* Supports ECDSA (default) and RSA certificate private keys.
* Can optionally install a http -> https redirect, so your site effectively
  runs https only.
* Fully automated.
* Configuration changes are logged and can be reverted.

.. Do not modify this comment unless you know what you're doing. tag:features-end
