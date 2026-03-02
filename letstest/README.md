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

These tests use the AWS SDK for Python (boto3) to manipulate EC2 instances.
Before running the tests, you'll need to set up credentials by following the
instructions at
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html#configuration.
You will also want to create a `~/.aws/config` file setting the region for your
profile to `us-east-1`, following the instructions in the boto3 quickstart guide above.

Lastly, you will want to create a file on your system containing a trusted SSH key
by following the instructions at
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html.

## Usage
To run tests, activate the virtual environment you created above and from this directory run:
```
>letstest targets/targets.yaml /path/to/your/key.pem <profile name> scripts/<test to run>
```

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
- https://github.com/certbot/certbot
