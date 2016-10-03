## Route53 plugin for Let's Encrypt client


### Before you start

It's expected that the root hosted zone for the domain in question already exists in your account.

### Setup

1. Create a virtual environment

2. Make sure you have libssl-dev (or your regional equivalent) installed.

3. Install by adding these to your requirements.txt file:

```
--no-binary pycparser
-e git+https://github.com/certbot/certbot.git#egg=certbot
-e git+https://github.com/certbot/certbot.git#egg=acme&subdirectory=acme
hpeixoto-letsencrypt-route53
```

We need DNS01 support in certbot, which is only available in master for now.
Additionally, pycparser suffers from
https://github.com/eliben/pycparser/issues/148, which is why we need to
recompile it, which depends on `libssl-dev`.

### How to use it

Make sure you have access to AWS's Route53 service, either through IAM roles or
via `.aws/credentials`.

To generate a certificate:
```
letsencrypt certonly \
  -n --agree-tos --email DEVOPS@COMPANY.COM \
  -a hpeixoto-letsencrypt-route53:auth \
  -d MY.DOMAIN.NAME
```
