"""
The `~certbot_dns_standalone.dns_standalone` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by using an
integrated DNS server.

This allows using CNAME records to direct validation elsewhere in case of
domains not under your control or when simply wanting to avoid making changes
to the DNS records. You only need an IP address with a free port 53.

First you need to choose a subdomain that you will use, e.g.
`acme.example.com`.

Next, you need to configure the relevant NS and A records

.. code-block:: none

   acme     IN  NS  ns.acme.example.com.
   ns.acme  IN  A   1.2.3.4

where `1.2.3.4` the IP of the server that will be running `certbot`.

Next, you need to configure `_acme-challenge` as a CNAME record to point to
`domain.acme.example.com`, e.g.:

.. code-block:: none

   _acme-challenge  IN  CNAME  example.org.acme.example.com.

where `example.org` is the domain you are requesting the certificate for. The
domain name itself is not used anywhere, but it is a good practice to specify
it anyway.


Named Arguments
---------------

========================================  =====================================
``--dns-standalone-address``              IP address to bind to
                                          (default: 0.0.0.0)
========================================  =====================================


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com`` using the IP
             ``1.2.3.4``

   certbot certonly \\
     --dns-standalone \\
     --dns-standalone-address 1.2.3.4 \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com`` using the IP ``1.2.3.4``

   certbot certonly \\
     --dns-standalone \\
     --dns-standalone-address 1.2.3.4 \\
     -d example.com \\
     -d www.example.com

"""
