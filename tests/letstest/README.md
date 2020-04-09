# letstest
Simple AWS testfarm scripts for certbot client testing

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

## Installation and configuration
These tests require Python 3, awscli, boto3, PyYAML, and fabric 2.0+. If you
have Python 3 installed, you can use requirements.txt to create a virtual
environment with a known set of dependencies by running:
```
python3 -m venv venv3
. ./venv3/bin/activate
pip install --requirement requirements.txt
```

You can then configure AWS credentials and create a key by running:
```
>aws configure --profile <profile name>
[interactive: enter secrets for IAM role]
>aws ec2 create-key-pair --profile <profile name> --key-name <key name> --query 'KeyMaterial' --output text > whatever/path/you/want.pem
```
Note: whatever you pick for `<key name>` will be shown to other users with AWS access.

When prompted for a default region name, enter: `us-east-1`.

## Usage
To run tests, activate the virtual environment you created above and run:
```
>python multitester.py targets.yaml /path/to/your/key.pem <profile name> scripts/<test to run>
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

A folder named `letest-<timestamp>` is also created with a log file from each instance of the test and a file named "results" containing the output above.
The tests take quite a while to run.

Also, the way all of the tests work is to check if there is already a boulder server running and if not start one. The boulder server is left running between tests,
and there are known issues if two instances of boulder attempt to be started. After starting your first test, wait until you see "Found existing boulder server:" or if you see output
about creating a boulder server, wait a minute before starting the 2nd test. You only have to do this after starting your first session of tests or after running
the `aws ec2 terminate-instances` command above.

## Scripts
Example scripts are in the 'scripts' directory, these are just bash scripts that have a few parameters passed
to them at runtime via environment variables.  test_apache2.sh is a useful reference.

Note that the <pre>test_letsencrypt_auto_*</pre> scripts pull code from PyPI using the letsencrypt-auto script,
__not__ the local python code.  test_apache2 runs the dev venv and does local tests.

See:
- https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
- https://docs.aws.amazon.com/cli/latest/userguide/cli-ec2-keypairs.html

Main repos:
- https://github.com/letsencrypt/boulder
- https://github.com/letsencrypt/letsencrypt
