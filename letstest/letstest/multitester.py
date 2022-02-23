"""
Certbot Integration Test Tool

- Launches EC2 instances with a given list of AMIs for different distros
- Copies certbot repo and puts it on the instances
- Runs certbot tests (bash scripts) on all of these
- Logs execution and success/fail for debugging

Notes:
  - Some AWS images, e.g. official CentOS and FreeBSD images
    require acceptance of user terms on the AWS marketplace
    website.  This can't be automated.
  - AWS EC2 has a default limit of 20 t2/t1 instances, if more
    are needed, they need to be requested via online webform.

Usage:
  - Requires AWS IAM secrets to be set up with aws cli
  - Requires an AWS associated keyfile <keyname>.pem

>aws configure --profile HappyHacker
[interactive: enter secrets for IAM role]
>aws ec2 create-key-pair --profile HappyHacker --key-name MyKeyPair \
 --query 'KeyMaterial' --output text > MyKeyPair.pem
then:
>letstest targets/targets.yaml MyKeyPair.pem HappyHacker scripts/test_apache2.sh
see:
  https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
  https://docs.aws.amazon.com/cli/latest/userguide/cli-ec2-keypairs.html
"""
import argparse
import multiprocessing as mp
from multiprocessing import Manager
import os
import socket
import sys
import tempfile
import time
import traceback
import urllib.error as urllib_error
import urllib.request as urllib_request

import boto3
from botocore.exceptions import ClientError
import yaml

from fabric import Config
from fabric import Connection

# Command line parser
#-------------------------------------------------------------------------------
parser = argparse.ArgumentParser(description='Builds EC2 cluster for testing.')
parser.add_argument('config_file',
                    help='yaml configuration file for AWS server cluster')
parser.add_argument('key_file',
                    help='key file (<keyname>.pem) for AWS')
parser.add_argument('aws_profile',
                    help='profile for AWS (i.e. as in ~/.aws/certificates)')
parser.add_argument('test_script',
                    default='test_apache2.sh',
                    help='path of bash script in to deploy and run')
parser.add_argument('--repo',
                    default='https://github.com/letsencrypt/letsencrypt.git',
                    help='certbot git repo to use')
parser.add_argument('--branch',
                    default='~',
                    help='certbot git branch to trial')
parser.add_argument('--pull_request',
                    default='~',
                    help='letsencrypt/letsencrypt pull request to trial')
parser.add_argument('--merge_master',
                    action='store_true',
                    help="if set merges PR into master branch of letsencrypt/letsencrypt")
parser.add_argument('--saveinstances',
                    action='store_true',
                    help="don't kill EC2 instances after run, useful for debugging")
parser.add_argument('--alt_pip',
                    default='',
                    help="server from which to pull candidate release packages")
cl_args = parser.parse_args()

# Credential Variables
#-------------------------------------------------------------------------------
# assumes naming: <key_filename> = <keyname>.pem
KEYFILE = cl_args.key_file
KEYNAME = os.path.split(cl_args.key_file)[1].split('.pem')[0]
PROFILE = None if cl_args.aws_profile == 'SET_BY_ENV' else cl_args.aws_profile

# Globals
#-------------------------------------------------------------------------------
SECURITY_GROUP_NAME = 'certbot-security-group'
SENTINEL = None #queue kill signal
SUBNET_NAME = 'certbot-subnet'

class Status:
    """Possible statuses of client tests."""
    PASS = 'pass'
    FAIL = 'fail'

# Boto3/AWS automation functions
#-------------------------------------------------------------------------------
def should_use_subnet(subnet):
    """Should we use the given subnet for these tests?

    We should if it is the default subnet for the availability zone or the
    subnet is named "certbot-subnet".

    """
    if not subnet.map_public_ip_on_launch:
        return False
    if subnet.default_for_az:
        return True
    for tag in subnet.tags:
        if tag['Key'] == 'Name' and tag['Value'] == SUBNET_NAME:
            return True
    return False

def make_security_group(vpc):
    """Creates a security group in the given VPC."""
    # will fail if security group of GroupName already exists
    # cannot have duplicate SGs of the same name
    mysg = vpc.create_security_group(GroupName=SECURITY_GROUP_NAME,
                                     Description='security group for automated testing')
    mysg.authorize_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0", FromPort=22, ToPort=22)
    # for mosh
    mysg.authorize_ingress(IpProtocol="udp", CidrIp="0.0.0.0/0", FromPort=60000, ToPort=61000)
    return mysg

def make_instance(ec2_client,
                  instance_name,
                  ami_id,
                  keyname,
                  security_group_id,
                  subnet_id,
                  self_destruct,
                  machine_type='t2.micro'):
    """Creates an instance using the given parameters.

    If self_destruct is True, the instance will be configured to shutdown after
    1 hour and to terminate itself on shutdown.

    """
    block_device_mappings = _get_block_device_mappings(ec2_client, ami_id)
    tags = [{'Key': 'Name', 'Value': instance_name}]
    tag_spec = [{'ResourceType': 'instance', 'Tags': tags}]
    kwargs = {
        'BlockDeviceMappings': block_device_mappings,
        'ImageId': ami_id,
        'SecurityGroupIds': [security_group_id],
        'SubnetId': subnet_id,
        'KeyName': keyname,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': machine_type,
        'TagSpecifications': tag_spec
    }
    if self_destruct:
            kwargs['InstanceInitiatedShutdownBehavior'] = 'terminate'
            kwargs['UserData'] = '#!/bin/bash\nshutdown -P +60\n'
    return ec2_client.create_instances(**kwargs)[0]

def _get_block_device_mappings(ec2_client, ami_id):
    """Returns the list of block device mappings to ensure cleanup.

    This list sets connected EBS volumes to be deleted when the EC2
    instance is terminated.

    """
    # Not all devices use EBS, but the default value for DeleteOnTermination
    # when the device does use EBS is true. See:
    # * https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-mapping.html
    # * https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-template.html
    return [{'DeviceName': mapping['DeviceName'],
             'Ebs': {'DeleteOnTermination': True}}
            for mapping in ec2_client.Image(ami_id).block_device_mappings
            if not mapping.get('Ebs', {}).get('DeleteOnTermination', True)]


# Helper Routines
#-------------------------------------------------------------------------------
def block_until_ssh_open(ipstring, wait_time=10, timeout=120):
    "Blocks until server at ipstring has an open port 22"
    reached = False
    t_elapsed = 0
    while not reached and t_elapsed < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ipstring, 22))
            reached = True
        except socket.error as err:
            time.sleep(wait_time)
            t_elapsed += wait_time
    sock.close()

def block_until_instance_ready(booting_instance, extra_wait_time=20):
    "Blocks booting_instance until AWS EC2 instance is ready to accept SSH connections"
    booting_instance.wait_until_running()
    # The instance needs to be reloaded to update its local attributes. See
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Instance.reload.
    booting_instance.reload()
    # After waiting for the instance to be running and reloading the instance
    # state, we should have an IP address.
    assert booting_instance.public_ip_address is not None
    block_until_ssh_open(booting_instance.public_ip_address)
    time.sleep(extra_wait_time)
    return booting_instance


# Fabric Routines
#-------------------------------------------------------------------------------
def local_git_clone(local_cxn, repo_url, log_dir):
    """clones master of repo_url"""
    local_cxn.local('cd %s && if [ -d letsencrypt ]; then rm -rf letsencrypt; fi' % log_dir)
    local_cxn.local('cd %s && git clone %s letsencrypt'% (log_dir, repo_url))
    local_cxn.local('cd %s && tar czf le.tar.gz letsencrypt'% log_dir)

def local_git_branch(local_cxn, repo_url, branch_name, log_dir):
    """clones branch <branch_name> of repo_url"""
    local_cxn.local('cd %s && if [ -d letsencrypt ]; then rm -rf letsencrypt; fi' % log_dir)
    local_cxn.local('cd %s && git clone %s letsencrypt --branch %s --single-branch'%
        (log_dir, repo_url, branch_name))
    local_cxn.local('cd %s && tar czf le.tar.gz letsencrypt' % log_dir)

def local_git_PR(local_cxn, repo_url, PRnumstr, log_dir, merge_master=True):
    """clones specified pull request from repo_url and optionally merges into master"""
    local_cxn.local('cd %s && if [ -d letsencrypt ]; then rm -rf letsencrypt; fi' % log_dir)
    local_cxn.local('cd %s && git clone %s letsencrypt' % (log_dir, repo_url))
    local_cxn.local('cd %s && cd letsencrypt && '
        'git fetch origin pull/%s/head:lePRtest' % (log_dir, PRnumstr))
    local_cxn.local('cd %s && cd letsencrypt && git checkout lePRtest' % log_dir)
    if merge_master:
        local_cxn.local('cd %s && cd letsencrypt && git remote update origin' % log_dir)
        local_cxn.local('cd %s && cd letsencrypt && '
            'git merge origin/master -m "testmerge"' % log_dir)
    local_cxn.local('cd %s && tar czf le.tar.gz letsencrypt' % log_dir)

def local_repo_to_remote(cxn, log_dir):
    """copies local tarball of repo to remote"""
    filename = 'le.tar.gz'
    local_path = os.path.join(log_dir, filename)
    cxn.put(local=local_path, remote='')
    cxn.run('tar xzf %s' % filename)

def local_repo_clean(local_cxn, log_dir):
    """delete tarball"""
    filename = 'le.tar.gz'
    local_path = os.path.join(log_dir, filename)
    local_cxn.local('rm %s' % local_path)

def deploy_script(cxn, scriptpath, *args):
    """copies to remote and executes local script"""
    cxn.put(local=scriptpath, remote='', preserve_mode=True)
    scriptfile = os.path.split(scriptpath)[1]
    args_str = ' '.join(args)
    cxn.run('./'+scriptfile+' '+args_str)

def install_and_launch_certbot(cxn, instance, target, log_dir):
    local_repo_to_remote(cxn, log_dir)
    # This needs to be like this, I promise. 1) The env argument to run doesn't work.
    # See https://github.com/fabric/fabric/issues/1744. 2) prefix() sticks an && between
    # the commands, so it needs to be exports rather than no &&s in between for the script subshell.
    with cxn.prefix('export PUBLIC_IP=%s && export PRIVATE_IP=%s && '
                    'export PUBLIC_HOSTNAME=%s && export PIP_EXTRA_INDEX_URL=%s && '
                    'export OS_TYPE=%s' %
                    (instance.public_ip_address,
                    instance.private_ip_address,
                    instance.public_dns_name,
                    cl_args.alt_pip,
                    target['type'])):
        deploy_script(cxn, cl_args.test_script)

def grab_certbot_log(cxn):
    "grabs letsencrypt.log via cat into logged stdout"
    cxn.sudo('/bin/bash -l -i -c \'if [ -f "/var/log/letsencrypt/letsencrypt.log" ]; then ' +
        'cat "/var/log/letsencrypt/letsencrypt.log"; else echo "[novarlog]"; fi\'')
    # fallback file if /var/log is unwriteable...? correct?
    cxn.sudo('/bin/bash -l -i -c \'if [ -f ./certbot.log ]; then ' +
        'cat ./certbot.log; else echo "[nolocallog]"; fi\'')


def create_client_instance(ec2_client, target, security_group_id, subnet_id, self_destruct):
    """Create a single client instance for running tests."""
    if 'machine_type' in target:
        machine_type = target['machine_type']
    elif target['virt'] == 'hvm':
        machine_type = 't2.medium'
    else:
        # 32 bit systems
        machine_type = 'c1.medium'
    name = 'le-%s'%target['name']
    print(name, end=" ")
    return make_instance(ec2_client,
                         name,
                         target['ami'],
                         KEYNAME,
                         machine_type=machine_type,
                         security_group_id=security_group_id,
                         subnet_id=subnet_id,
                         self_destruct=self_destruct)


def test_client_process(fab_config, inqueue, outqueue, log_dir):
    cur_proc = mp.current_process()
    for inreq in iter(inqueue.get, SENTINEL):
        ii, instance_id, target = inreq

        # Each client process is given its own session due to the suggestion at
        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html?highlight=multithreading#multithreading-multiprocessing.
        aws_session = boto3.session.Session(profile_name=PROFILE)
        ec2_client = aws_session.resource('ec2')
        instance = ec2_client.Instance(id=instance_id)

        #save all stdout to log file
        sys.stdout = open(log_dir+'/'+'%d_%s.log'%(ii,target['name']), 'w')

        print("[%s : client %d %s %s]" % (cur_proc.name, ii, target['ami'], target['name']))
        instance = block_until_instance_ready(instance)
        print("server %s at %s"%(instance, instance.public_ip_address))
        host_string = "%s@%s"%(target['user'], instance.public_ip_address)
        print(host_string)

        with Connection(host_string, config=fab_config) as cxn:
            try:
                install_and_launch_certbot(cxn, instance, target, log_dir)
                outqueue.put((ii, target, Status.PASS))
                print("%s - %s SUCCESS"%(target['ami'], target['name']))
            except:
                outqueue.put((ii, target, Status.FAIL))
                print("%s - %s FAIL"%(target['ami'], target['name']))
                traceback.print_exc(file=sys.stdout)
                pass

            # append server certbot.log to each per-machine output log
            print("\n\ncertbot.log\n" + "-"*80 + "\n")
            try:
                grab_certbot_log(cxn)
            except:
                print("log fail\n")
                traceback.print_exc(file=sys.stdout)
                pass


def cleanup(cl_args, instances, targetlist, log_dir):
    print('Logs in ', log_dir)
    # If lengths of instances and targetlist aren't equal, instances failed to
    # start before running tests so leaving instances running for debugging
    # isn't very useful. Let's cleanup after ourselves instead.
    if len(instances) != len(targetlist) or not cl_args.saveinstances:
        print('Terminating EC2 Instances')
        for instance in instances:
            instance.terminate()
    else:
        # print login information for the boxes for debugging
        for ii, target in enumerate(targetlist):
            print(target['name'],
                  target['ami'],
                  "%s@%s"%(target['user'], instances[ii].public_ip_address))


def main():
    # Fabric library controlled through global env parameters
    fab_config = Config(overrides={
        "connect_kwargs": {
            "key_filename": [KEYFILE], # https://github.com/fabric/fabric/issues/2007
        },
        "run": {
            "echo": True,
            "pty": True,
        },
        "timeouts": {
            "connect": 10,
        },
    })
    # no network connection, so don't worry about closing this one.
    local_cxn = Connection('localhost', config=fab_config)

    # Set up local copy of git repo
    #-------------------------------------------------------------------------------
    log_dir = tempfile.mkdtemp()  # points to logging / working directory
    print("Local dir for test repo and logs: %s"%log_dir)

    try:
        # figure out what git object to test and locally create it in log_dir
        print("Making local git repo")
        if cl_args.pull_request != '~':
            print('Testing PR %s ' % cl_args.pull_request,
                  "MERGING into master" if cl_args.merge_master else "")
            local_git_PR(local_cxn, cl_args.repo, cl_args.pull_request, log_dir,
                         cl_args.merge_master)
        elif cl_args.branch != '~':
            print('Testing branch %s of %s' % (cl_args.branch, cl_args.repo))
            local_git_branch(local_cxn, cl_args.repo, cl_args.branch, log_dir)
        else:
            print('Testing current branch of %s' % cl_args.repo, log_dir)
            local_git_clone(local_cxn, cl_args.repo, log_dir)
    except BaseException:
        print("FAIL: trouble with git repo")
        traceback.print_exc()
        exit(1)


    # Set up EC2 instances
    #-------------------------------------------------------------------------------
    configdata = yaml.safe_load(open(cl_args.config_file, 'r'))
    targetlist = configdata['targets']
    print('Testing against these images: [%d total]'%len(targetlist))
    for target in targetlist:
        print(target['ami'], target['name'])

    print("Connecting to EC2 using\n profile %s\n keyname %s\n keyfile %s"%(PROFILE, KEYNAME, KEYFILE))
    aws_session = boto3.session.Session(profile_name=PROFILE)
    ec2_client = aws_session.resource('ec2')

    print("Determining Subnet")
    for subnet in ec2_client.subnets.all():
        if should_use_subnet(subnet):
            subnet_id = subnet.id
            vpc_id = subnet.vpc.id
            break
    else:
        print("No usable subnet exists!")
        print("Please create a VPC with a subnet named {0}".format(SUBNET_NAME))
        print("that maps public IPv4 addresses to instances launched in the subnet.")
        sys.exit(1)

    print("Making Security Group")
    vpc = ec2_client.Vpc(vpc_id)
    sg_exists = False
    for sg in vpc.security_groups.all():
        if sg.group_name == SECURITY_GROUP_NAME:
            security_group_id = sg.id
            sg_exists = True
            print("  %s already exists"%SECURITY_GROUP_NAME)
    if not sg_exists:
        security_group_id = make_security_group(vpc).id
        time.sleep(30)

    instances = []
    try:
        print("Creating instances: ", end="")
        # If we want to preserve instances, do not have them self-destruct.
        self_destruct = not cl_args.saveinstances
        for target in targetlist:
            instances.append(
                create_client_instance(ec2_client, target,
                                       security_group_id, subnet_id,
                                       self_destruct)
            )
        print()

        # Install and launch client scripts in parallel
        #-------------------------------------------------------------------------------
        print("Uploading and running test script in parallel: %s"%cl_args.test_script)
        print("Output routed to log files in %s"%log_dir)
        # (Advice: always use Manager.Queue, never regular multiprocessing.Queue
        # the latter has implementation flaws that deadlock it in some circumstances)
        manager = Manager()
        outqueue = manager.Queue()
        inqueue = manager.Queue()

        # launch as many processes as clients to test
        num_processes = len(targetlist)
        jobs = [] #keep a reference to current procs


        # initiate process execution
        client_process_args=(fab_config, inqueue, outqueue, log_dir)
        for i in range(num_processes):
            p = mp.Process(target=test_client_process, args=client_process_args)
            jobs.append(p)
            p.daemon = True  # kills subprocesses if parent is killed
            p.start()

        # fill up work queue
        for ii, target in enumerate(targetlist):
            inqueue.put((ii, instances[ii].id, target))

        # add SENTINELs to end client processes
        for i in range(num_processes):
            inqueue.put(SENTINEL)
        print('Waiting on client processes', end='')
        for p in jobs:
            while p.is_alive():
                p.join(5 * 60)
                # Regularly print output to keep Travis happy
                print('.', end='')
                sys.stdout.flush()
        print()
        # add SENTINEL to output queue
        outqueue.put(SENTINEL)

        # clean up
        local_repo_clean(local_cxn, log_dir)

        # print and save summary results
        results_file = open(log_dir+'/results', 'w')
        outputs = list(iter(outqueue.get, SENTINEL))
        outputs.sort(key=lambda x: x[0])
        failed = False
        results_msg = ""
        for outq in outputs:
            ii, target, status = outq
            if status == Status.FAIL:
                failed = True
                with open(log_dir+'/'+'%d_%s.log'%(ii,target['name']), 'r') as f:
                    print(target['name'] + " test failed. Test log:")
                    print(f.read())
            results_msg = results_msg + '%d %s %s\n'%(ii, target['name'], status)
            results_file.write('%d %s %s\n'%(ii, target['name'], status))
        print(results_msg)
        if len(outputs) != num_processes:
            failed = True
            failure_message = 'FAILURE: Some target machines failed to run and were not tested. ' +\
                'Tests should be rerun.'
            print(failure_message)
            results_file.write(failure_message + '\n')
        results_file.close()

        if failed:
            sys.exit(1)

    finally:
        cleanup(cl_args, instances, targetlist, log_dir)


if __name__ == '__main__':
    main()
