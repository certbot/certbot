# Let's Encrypt

[![Build Status](https://travis-ci.org/letsencrypt/lets-encrypt-preview.svg?branch=master)]
(https://travis-ci.org/letsencrypt/lets-encrypt-preview)

## Disclaimer

This is the [Let's Encrypt] Agent **DEVELOPER PREVIEW** repository.

**DO NOT RUN THIS CODE ON A PRODUCTION WEBSERVER. IT WILL INSTALL
CERTIFICATES SIGNED BY A TEST CA, AND WILL CAUSE CERT WARNINGS FOR
USERS.**

This code is intended for testing, demonstration, and integration
engineering with OSes and hosting platforms. For the time being
project focuses on Linux and Apache, though we will be expanding
it to other platforms.

## Running the demo code

The demo code is supported and known to work on **Ubuntu only** (even
closely related [Debian is known to fail]
(https://github.com/letsencrypt/lets-encrypt-preview/issues/68)).
Therefore, prerequisites for other platforms listed below are provided
mainly for the [developers](#hacking) reference.

### Prerequisites

In general:

* [swig] is required for compiling [m2crypto]
* [augeas] is required for the `python-augeas` bindings

#### Ubuntu

```
sudo apt-get install python python-setuptools python-virtualenv \
  python-dev gcc swig dialog libaugeas0 libssl-dev
```

#### Mac OSX

`sudo brew install augeas swig`

### Installation

```
virtualenv --no-site-packages venv
./venv/bin/python setup.py install
sudo ./venv/bin/letsencrypt
```

## Hacking

1. Bootstrap: `./venv/bin/python setup.py dev`

2. Test code base: `./venv/bin/tox`

## Command line usage

```
usage: sudo letsencrypt.py [-h] [-d DOMAIN [DOMAIN ...]] [-s SERVER] [-p PRIVKEY]
                      [-c CSR] [-b ROLLBACK] [-k] [-v] [-r] [-n] [-e] [-t]
                      [--test]

An ACME client that can update Apache configurations.

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN [DOMAIN ...], --domains DOMAIN [DOMAIN ...]
  -s SERVER, --server SERVER
                        The ACME CA server address.
  -p PRIVKEY, --privkey PRIVKEY
                        Path to the private key file for certificate
                        generation.
  -c CSR, --csr CSR     Path to the certificate signing request file
                        corresponding to the private key file. The private key
                        file argument is required if this argument is
                        specified.
  -b ROLLBACK, --rollback ROLLBACK
                        Revert configuration <ROLLBACK> number of checkpoints.
  -k, --revoke          Revoke a certificate.
  -v, --view-checkpoints
                        View checkpoints and associated configuration changes.
  -r, --redirect        Automatically redirect all HTTP traffic to HTTPS for
                        the newly authenticated vhost.
  -n, --no-redirect     Skip the HTTPS redirect question, allowing both HTTP
                        and HTTPS.
  -e, --agree-eula      Skip the end user license agreement screen.
  -t, --text            Use the text output instead of the curses UI.
  --test                Run in test mode.
```

## More Information

- Further setup, documentation and open projects are available in the
  [Wiki].

- Join us at our IRC channel: #letsencrypt at [Freenode].

- Client software development can be discussed on this [mailing
  list]. To subscribe without a Google account, send an email to
  <client-dev+subscribe@letsencrypt.org>.


[augeas]: http://augeas.net
[Freenode]: https://freenode.net
[Let's Encrypt]: https://letsencrypt.org
[m2crypto]: https://github.com/M2Crypto/M2Crypto
[mailing list]: https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev
[swig]: http://www.swig.org
[wiki]: https://github.com/letsencrypt/lets-encrypt-preview/wiki
