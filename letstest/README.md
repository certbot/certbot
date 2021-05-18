# letstest
Simple AWS testfarm scripts for certbot client testing

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

## Installation and configuration

This package is installed in the Certbot development environment that is
created by following the instructions at
https://certbot.eff.org/docs/contributing.html#running-a-local-copy-of-the-client.

After activating that virtual environment, you can then configure AWS
credentials and create a key by running:
```
>aws configure --profile <profile name>
[interactive: enter secrets for IAM role]
>aws ec2 create-key-pair --profile <profile name> --key-name <key name> --query 'KeyMaterial' --output text > whatever/path/you/want.pem
```
Note: whatever you pick for `<key name>` will be shown to other users with AWS access.

When prompted for a default region name, enter: `us-east-1`.

## Usage
To run tests, activate the virtual environment you created above and from this directory run:
```
>letstest targets/targets.yaml /path/to/your/key.pem <profile name> scripts/<test to run>
```

You can only run up to two tests at once. The following error is often indicative of there being too many AWS instances running on our account:
```
NameError: name 'instances' is not defined
```

If you see this, you can run the following command to shut down all running instances:
```
aws ec2 terminate-instances --profile <profile name> --instance-ids $(aws ec2 describe-instances --profile <profile name> | grep <key name> | cut -f8)
```

It will take a minute for these instances to shut down and become available again. Running this will invalidate any in progress tests.

A temporary directory whose name is output by the tests is also created with a log file from each instance of the test and a file named "results" containing the output above.
The tests take quite a while to run.

## Scripts
Example scripts are in the 'scripts' directory, these are just bash scripts that have a few parameters passed
to them at runtime via environment variables.  test_apache2.sh is a useful reference.

test_apache2 runs the dev venv and does local tests.

See:
- https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
- https://docs.aws.amazon.com/cli/latest/userguide/cli-ec2-keypairs.html

Main repos:
- https://github.com/letsencrypt/letsencrypt
