# letstest
simple aws testfarm scripts for letsencrypt client testing

- Configures (canned) boulder server
- Launches EC2 instances with a given list of AMIs for different distros
- Copies letsencrypt repo and puts it on the instances
- Runs letsencrypt tests (bash scripts) on all of these
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
>python multitester.py targets.yaml MyKeyPair.pem HappyHacker scripts/test_letsencrypt_auto_venv_only.sh
```

see:
  https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
  https://docs.aws.amazon.com/cli/latest/userguide/cli-ec2-keypairs.html

https://github.com/letsencrypt/boulder
https://github.com/letsencrypt/letsencrypt