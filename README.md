## Route53 plugin for Let's Encrypt client


### Before you start

It's expected that the root hosted zone for the domain in question already exists in your account.

### Setup

1. Install the letsencrypt client [https://letsencrypt.readthedocs.org/en/latest/using.html#installation](https://letsencrypt.readthedocs.org/en/latest/using.html#installation)

  ```
  pip install letsencrypt
  ```

1. Install the letsencrypt-route53 plugin

  ```
  pip install letsencrypt-route53
  ```

### How to use it

To generate a certificate and install it in a CloudFront distribution:
```
AWS_ACCESS_KEY_ID="your_key" \
AWS_SECRET_ACCESS_KEY="your_secret" \
letsencrypt --agree-tos -a letsencrypt-route53:auth \
-d the_domain
```

Follow the screen prompts and you should end up with the certificate in your
distribution. It may take a couple minutes to update.

To automate the renewal process without prompts (for example, with a monthly cron), you can add the letsencrypt parameters --renew-by-default --text
