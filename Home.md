# Welcome to the lets-encrypt-preview wiki!

## Getting Started!

This client is being designed to follow the [ACME protocol](https://github.com/letsencrypt/acme-spec).  The protocol is subject to change, but most changes should mainly effect logic in client.py (which is not overly complex and should be static from one webserver to another)

### Client Installation

Checkout the README.md and follow the instructions to get the Let's Encrypt Client setup.  Pleases submit an issue if the process doesn't work for you and you would like to contribute.

This client has only been tested on versions of Ubuntu LTS.  I will try to update this as I attempt more distributions.

### Setting up your own ACME server
Benefits:
* You can direct the server to domain names you do not own
* You can modify the server to print logs with better error messages when things go wrong.

When you pull the code from the repository.  The CONFIG file (located at letsencrypt/client/CONFIG.py) contains a reference to "letsencrypt-demo.org" which is a very basic ACME demo CA we have running behind a browser trusted certificate (You can get your own demo server by downloading the node-acme repository and setting it up).

The ACME client will not be able to speak to any demo server unless the server is behind a certificate that is trusted by your system for the given name.  (You may modify the client to disable certificate checking, but this solution is not recommended)

You have 3 options:

One: You can generate a self-signed certificate for the server domain.
```openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt```

Then install that certificate as a trusted certificate on the box running the Let's Encrypt client, by following these [steps.]
(http://kb.kerio.com/product/kerio-connect/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html)

Two: Use Let's Encrypt demo to bootstrap!  You have a domain name for your server (demo CA). You authenticate and get a certificate from our demo CA. You then install that certificate as a trusted certificate on your client box.

Three: If you have a spare domain name you can get a browser trusted certificate and set it up on your server. If you haven't gone through the process before it might be a good learning experience. :)

Once you have your own server running, you can point the server to your client with any domain by modifying the /etc/hosts file.  You can now configure your server to host any domains that you please and test a variety of configurations.

This setup should allow you to do rapid testing in the future.  I would like to create an automatic testing process that would allow all additions of the code base to be automatically and thoroughly tested using different example configurations. More on this in the "How to Contribute" section.