## Route53 plugin for Let's Encrypt client

### Before you start

It's expected that the root hosted zone for the domain in question already
exists in your account.

### Setup

1. Create a virtual environment

2. Update its pip and setuptools (`VENV/bin/pip install -U setuptools pip`)
to avoid problems with cryptography's dependency on setuptools>=11.3.

3. Make sure you have libssl-dev and libffi (or your regional equivalents)
installed. You might have to set compiler flags to pick things up (I have to
use `CPPFLAGS=-I/usr/local/opt/openssl/include
LDFLAGS=-L/usr/local/opt/openssl/lib` on my macOS to pick up brew's openssl,
for example).

4. Install this package.

### How to use it

Make sure you have access to AWS's Route53 service, either through IAM roles or
via `.aws/credentials`. Check out
[sample-aws-policy.json](examples/sample-aws-policy.json) for the necessary permissions.

To generate a certificate:
```
certbot certonly \
  -n --agree-tos --email DEVOPS@COMPANY.COM \
  --dns-route53 \
  -d MY.DOMAIN.NAME
```
