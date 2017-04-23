Digital certificates can only be issued to people who are entitled to them. For example, assuming you don't run google.com, you're not entitled to a certificate for it. Nor is someone else entitled to receive a certificate for your web site.

In order to receive a certificate from Let's Encrypt certificate authority (CA), you have to prove your control over each of the domain names that will be listed in the certificate. You can do so by making certain publicly-visible changes, proving that the person who's requested a particular certificate is the same person who controls the site(s) that the certificate will refer to.

Let’s Encrypt specifies three different ways to prove your control over a domain (each of which Certbot may be able to do for you). These are called "challenges," because you are being challenged to perform tasks that only someone who controls the domain should be able to accomplish.

When you use Certbot, it will attempt to help you prove control over your domains automatically in a way that's acceptable to the CA. Especially if this doesn't work the way you expected, it can be helpful to understand what Certbot is trying to do in each case.

The three ways to prove your control over a domain for the Let’s Encrypt CA are:

* Posting a specified file on a web site

This method is called the HTTP-01 challenge.  In this challenge, the certificate authority will expect a specified file to be posted in a specified location on a web site.  The file will be downloaded using an HTTP request on TCP port 80.  Since part of what this challenge shows is the ability to create a file at an arbitrary location, you cannot choose a different location or port number.

* Offering a specified certificate on a web site

This method is called the TLS-SNI-01 challenge.  In this challenge, the certificate authority will expect a specified digital certificate to be provided by the web server in response to an HTTPS request using a particular made-up domain name.  The request will be made using HTTPS on TCP port 443.  You cannot choose a different port number.

This certificate is a self-signed certificate created by Certbot.  You use it only temporarily to prove your control over a domain name.  It’s not the same as the certificate for your site that will later be issued by Let's Encrypt once you've proven that you control the site.

* Posting a specified DNS record in the domain name system

This method is called the DNS-01 challenge.  In this challenge, the certificate authority will expect a specified DNS record to be present in your DNS zone when queried for.  The record will be a TXT record for a specific subdomain of the name you're proving your control over.

For each kind of challenge, the challenge can potentially be completed *automatically* (Certbot directly makes the necessary changes itself, or runs another program that does so), or *manually* (Certbot tells you to make a certain change, and you edit a configuration file of some kind in order to accomplish it).  Certbot's design emphasizes performing challenges *automatically*, and this is the normal case for most uses of Certbot.

Some Certbot *plugins* offer the functionality of an *authenticator*, which simply means that they can satisfy challenges. Different plugins can satisfy different kinds of challenges, as follows:

apache plugin: Can only use TLS-SNI-01.  Tries to edit your Apache configuration files in order to temporarily serve a specified Certbot-generated certificate for a specified name.  This can work when you're running Certbot on a web server with an existing installation of Apache that is able to listen on port 443. This makes certain assumptions about your Apache configuration.

nginx plugin: Can only use TLS-SNI-01.  Tries to edit your nginx configuration files in order to temporarily serve a specified Certbot-generated certificate for a specified name.  This can work when you're running Certbot on a web server with an existing installation of nginx that is able to listen on port 443. This makes certain assumptions about your nginx configuration.

webroot plugin: Can only use HTTP-01.  Tries to place a file into an appropriate place in order for that file to be served over HTTP on port 80 by an existing web server running on your system.  This can work when you're running Certbot on a web server with any existing server application that already listens to web requests on port 80, and that serves files from disk in response.

standalone plugin: Can use either TLS-SNI-01 or HTTP-01.  (You can choose with the `--preferred-challenges` option.)  Tries to run its own temporary web server which will speak either HTTP on port 80 (for HTTP-01) or HTTPS on port 443 (for TLS-SNI-01).  This can work if either of these ports is free to receive incoming connections at the moment that you run Certbot, because there's no existing program listening to them or because you've temporarily shut down any server application that was listening to them.

manual plugin: Can use either DNS-01 or HTTP-01.  May tell you what changes you are expected to make to your configuration.  Or, using an external script, can update your DNS records (for DNS-01) or your webroot (for HTTP-01).  This can work if you have appropriate technical knowledge of how to make these kinds of changes yourself when asked to do so.  Note that this will prevent automated renewal of your certificate using `certbot renew`.  [Can manual also use TLS-SNI-01??]


Common problems with passing different challenges

HTTP-01 challenge:
* (With webroot plugin) You aren't running Certbot on your web server

  Most people should install and run Certbot on their web server hosting their website, not on their laptops or some other computer.  While you can use Certbot in manual mode on a laptop and then separately set up the appropriate files on your webserver, it's not likely to be the most convenient way to get a certificate for most users.

* A domain name you're requesting a certificate for isn't correctly pointed at that web server

  In most cases, every name you're requesting a certificate for should already exist and be pointed to the public IP address of the server where you're requesting that certificate.  (Some alternatives exist for complex network configurations, but they're the exception rather than the rule.)

* A firewall is blocking access to port 80

  The certificate authority needs to be able to connect to port 80 of your server in order to confirm that you satisfied the HTTP-01 challenge.  So that needs to be publicly reachable from the Internet, and not blocked by a router or firewall.

* (With webroot plugin) You specified the webroot directory incorrectly

  If you used `--webroot`, you need to tell Certbot where it can put
  files in order to have them served by your existing web server.
  If you said your webroot for example.com was /var/www/example.com,
  then a file placed in /var/www/example.com/.well-known/acme-challenge/testfile should appear on
  your web site at http://example.com/.well-known/acme-challenge/testfile (which you can test using a web browser). (A redirection to HTTPS
  is OK here and should not stop the challenge from working.)

  Note that you should *not* specify the .well-known/acme-challenge directory itself.  Instead, you should specify the top level directory that web content is served from.

* (With webroot plugin) You don't have a webroot directory at all

  In some web server configurations, all pages are dynamically generated by some kind of framework, usually using a database backend.  In this case, there might not be a particular directory that files can be directly served from by the existing web server application.  Using the webroot plugin in this case requires making a change to your web server configuration first.

* (With manual plugin) You updated the webroot directory incorrectly

  If you used `--manual`, you need to know where you can put files in order to have them served by your existing web server. If you think your webroot for example.com is /var/www/example.com, then a file placed in /var/www/example.com/.well-known/acme-challenge/testfile should appear on
  your web site at http://example.com/.well-known/acme-challenge/testfile.  (A redirection to HTTPS
  is OK here and should not stop the challenge from working.) You should also make sure that you don't make a typo in the name of the file when creating it.

* Your existing web server's configuration refuses to serve files
  from /.well-known/acme-challenge, or doesn't serve them at the
  /.well-known/acme-challenge location on your site, or serves them
  with a header or footer, or serves them with an unusual MIME type.

* (With standalone plugin)
  You tried to use `--standalone` when there was already some other
  program on your server listening to port 80

* (With webroot plugin)
  You tried to use `--webroot` when you don't have an existing web
  server listening on port 80

* Your DNS records aren't valid
  Try checking your DNS records with a tool like the DNSchecker at
  http://www.dnsstuff.com/ to make sure there are no serious errors.
  Sometimes a DNS error still allows your site to load in a web
  browser, but prevents the certificate authority from issuing a
  certificate.

TLS-SNI-01 challenge:
* You aren't running Certbot on your web server

  Most people should install and run Certbot on their web server hosting their website, not on their laptops or some other computer.  While you can use Certbot in manual mode on a laptop and then separately set up the appropriate files on your webserver, it's not likely to be the most convenient way to get a certificate for most users.

* A domain name you're requesting a certificate for isn't correctly
  pointed at that web server

  In most cases, every name you're requesting a certificate for should
  already exist and be pointed to the server where you're requesting
  that certificate.  (Some alternatives exist for complex network
  configurations, but they're the exception rather than the rule.)

* You're using a content delivery network (CDN)

  TLS-SNI-01 doesn't work with CDNs (like CloudFlare and Akamai).  You
  have to use a different challenge type.  (This is a special case of
  the previous problem: the domain name is pointed at the CDN, not
  directly at your server.)

* A firewall is blocking access to port 443

  The certificate authority needs to be able to connect to port 443 of
  your server in order to confirm that you satisfied the TLS-SNI-01
  challenge.  So that needs to be publicly reachable from the Internet,
  and not blocked by a router or firewall.

* (With apache plugin)
  Certbot thinks you're running Apache, but you aren't running it, or
  you're running a different server of some kind on port 443

* (With nginx plugin)
  Certbot thinks you're running nginx, but you aren't running it, or
  you're running a different server of some kind on port 443

* (With apache or nginx plugin)
  Certbot doesn't know how to modify your web server configuration correctly

* (With standalone plugin)
  You tried to use `--standalone` when there was already some other
  program on your server listening to port 443

* Your DNS records aren't valid
  Try checking your DNS records with a tool like the DNSchecker at
  http://www.dnsstuff.com/ to make sure there are no serious errors.
  Sometimes a DNS error still allows your site to load in a web
  browser, but prevents the certificate authority from issuing a
  certificate.

DNS-01 challenge:

* (With manual plugin) Your DNS records weren't correctly updated.
  You need to be able to make appropriate changes to your DNS zone
  in order to pass the challenge.

* Your DNS records aren't valid.
  Try checking your DNS records with a tool like the DNSchecker at
  http://www.dnsstuff.com/ to make sure there are no serious errors.
  Sometimes a DNS error still allows your site to load in a web
  browser, but prevents the certificate authority from issuing a
  certificate.
