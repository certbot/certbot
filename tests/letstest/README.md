# letstest
simple aws testfarm scripts for certbot client testing

- Configures (canned) boulder server
- Launches EC2 instances with a given list of AMIs for different distros
- Copies certbot repo and puts it on the instances
- Runs certbot tests (bash scripts) on all of these
- Logs execution and success/fail for debugging

## Notes
  - Some AWS images, e.g. official CentOS and FreeBSD images
    require acceptance of user terms on the AWS marketplace
    website.  This can't be automated.
  - AWS EC2 has a default limit of 20 t2/t1 instances, if more
    are needed, they need to be requested via online webform.

## Usage
  - Requires AWS IAM secrets to be set up with aws cli
  - Requires an AWS associated keyfile <keyname>.pem

```
>aws configure --profile HappyHacker
[interactive: enter secrets for IAM role]
>aws ec2 create-key-pair --profile HappyHacker --key-name MyKeyPair --query 'KeyMaterial' --output text > MyKeyPair.pem
```
then:
```
>python multitester.py targets.yaml MyKeyPair.pem HappyHacker scripts/test_apache2.sh
```

## Scripts
example scripts are in the 'scripts' directory, these are just bash scripts that have a few parameters passed
to them at runtime via environment variables.  test_apache2.sh is a useful reference.

Note that the <pre>test_letsencrypt_auto_*</pre> scripts pull code from PyPI using the letsencrypt-auto script,
__not__ the local python code.  test_apache2 runs the dev venv and does local tests.

see:
- https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
- https://docs.aws.amazon.com/cli/latest/userguide/cli-ec2-keypairs.html

main repos:
- https://github.com/letsencrypt/boulder
- https://github.com/letsencrypt/letsencrypt
