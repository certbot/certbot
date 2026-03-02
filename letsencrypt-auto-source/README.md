# Legacy letsencrypt-auto files

`certbot-auto` and `letsencrypt-auto` were two names for the same self-updating
shell script that wrapped Certbot. Old versions of the script continue to rely
on pulling `letsencrypt-auto` and `letsencrypt-auto.sig` from this directory hosted on Github to download and
verify updates. We're keeping these files and the tests for them around to
prevent these old scripts from breaking.

If we need or want to remove these files and tests in the future, we can, but
before we do, we should write a Let's Encrypt forum post describing the error
message users will see and how they can work around the problem. See
https://github.com/certbot/certbot/issues/8812 for more info.
