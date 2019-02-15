"""
Certbot Integration Test Tool

- Configures (canned) boulder server
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
>python multitester.py targets.yaml MyKeyPair.pem HappyHacker scripts/test_letsencrypt_auto_venv_only.sh
see:
  https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
  https://docs.aws.amazon.com/cli/latest/userguide/cli-ec2-keypairs.html
"""

from __future__ import print_function
from __future__ import with_statement

import sys, os, time, argparse, socket, traceback
import multiprocessing as mp
from multiprocessing import Manager
import urllib2
import yaml
import boto3
from botocore.exceptions import ClientError
import fabric
from fabric.api import run, execute, local, env, sudo, cd, lcd
from fabric.operations import get, put
from fabric.context_managers import shell_env

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
                    default='test_letsencrypt_auto_certonly_standalone.sh',
                    help='path of bash script in to deploy and run')
#parser.add_argument('--script_args',
#                    nargs='+',
#                    help='space-delimited list of arguments to pass to the bash test script',
#                    required=False)
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
parser.add_argument('--killboulder',
                    action='store_true',
                    help="do not leave a persistent boulder server running")
parser.add_argument('--boulderonly',
                    action='store_true',
                    help="only make a boulder server")
parser.add_argument('--fast',
                    action='store_true',
                    help="use larger instance types to run faster (saves about a minute, probably not worth it)")
cl_args = parser.parse_args()

# Credential Variables
#-------------------------------------------------------------------------------
# assumes naming: <key_filename> = <keyname>.pem
KEYFILE = cl_args.key_file
KEYNAME = os.path.split(cl_args.key_file)[1].split('.pem')[0]
PROFILE = cl_args.aws_profile

# Globals
#-------------------------------------------------------------------------------
BOULDER_AMI = 'ami-5f490b35' # premade shared boulder AMI 14.04LTS us-east-1
LOGDIR = "" #points to logging / working directory
# boto3/AWS api globals
AWS_SESSION = None
EC2 = None
SECURITY_GROUP_NAME = 'certbot-security-group'
SUBNET_NAME = 'certbot-subnet'

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
    mysg.authorize_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0", FromPort=80, ToPort=80)
    mysg.authorize_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0", FromPort=443, ToPort=443)
    # for boulder wfe (http) server
    mysg.authorize_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0", FromPort=4000, ToPort=4000)
    # for mosh
    mysg.authorize_ingress(IpProtocol="udp", CidrIp="0.0.0.0/0", FromPort=60000, ToPort=61000)
    return mysg

def make_instance(instance_name,
                  ami_id,
                  keyname,
                  security_group_id,
                  subnet_id,
                  machine_type='t2.micro',
                  userdata=""): #userdata contains bash or cloud-init script

    new_instance = EC2.create_instances(
        BlockDeviceMappings=_get_block_device_mappings(ami_id),
        ImageId=ami_id,
        SecurityGroupIds=[security_group_id],
        SubnetId=subnet_id,
        KeyName=keyname,
        MinCount=1,
        MaxCount=1,
        UserData=userdata,
        InstanceType=machine_type)[0]

    # brief pause to prevent rare error on EC2 delay, should block until ready instead
    time.sleep(1.0)

    # give instance a name
    try:
        new_instance.create_tags(Tags=[{'Key': 'Name', 'Value': instance_name}])
    except ClientError as e:
        if "InvalidInstanceID.NotFound" in str(e):
            # This seems to be ephemeral... retry
            time.sleep(1)
            new_instance.create_tags(Tags=[{'Key': 'Name', 'Value': instance_name}])
        else:
            raise
    return new_instance

def _get_block_device_mappings(ami_id):
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
            for mapping in EC2.Image(ami_id).block_device_mappings
            if not mapping.get('Ebs', {}).get('DeleteOnTermination', True)]


# Helper Routines
#-------------------------------------------------------------------------------
def block_until_http_ready(urlstring, wait_time=10, timeout=240):
    "Blocks until server at urlstring can respond to http requests"
    server_ready = False
    t_elapsed = 0
    while not server_ready and t_elapsed < timeout:
        try:
            sys.stdout.write('.')
            sys.stdout.flush()
            req = urllib2.Request(urlstring)
            response = urllib2.urlopen(req)
            #if response.code == 200:
            server_ready = True
        except urllib2.URLError:
            pass
        time.sleep(wait_time)
        t_elapsed += wait_time

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

def block_until_instance_ready(booting_instance, wait_time=5, extra_wait_time=20):
    "Blocks booting_instance until AWS EC2 instance is ready to accept SSH connections"
    # the reinstantiation from id is necessary to force boto3
    # to correctly update the 'state' variable during init
    _id = booting_instance.id
    _instance = EC2.Instance(id=_id)
    _state = _instance.state['Name']
    _ip = _instance.public_ip_address
    while _state != 'running' or _ip is None:
        time.sleep(wait_time)
        _instance = EC2.Instance(id=_id)
        _state = _instance.state['Name']
        _ip = _instance.public_ip_address
    block_until_ssh_open(_ip)
    time.sleep(extra_wait_time)
    return _instance


# Fabric Routines
#-------------------------------------------------------------------------------
def local_git_clone(repo_url):
    "clones master of repo_url"
    with lcd(LOGDIR):
        local('if [ -d letsencrypt ]; then rm -rf letsencrypt; fi')
        local('git clone %s letsencrypt'% repo_url)
        local('tar czf le.tar.gz letsencrypt')

def local_git_branch(repo_url, branch_name):
    "clones branch <branch_name> of repo_url"
    with lcd(LOGDIR):
        local('if [ -d letsencrypt ]; then rm -rf letsencrypt; fi')
        local('git clone %s letsencrypt --branch %s --single-branch'%(repo_url, branch_name))
        local('tar czf le.tar.gz letsencrypt')

def local_git_PR(repo_url, PRnumstr, merge_master=True):
    "clones specified pull request from repo_url and optionally merges into master"
    with lcd(LOGDIR):
        local('if [ -d letsencrypt ]; then rm -rf letsencrypt; fi')
        local('git clone %s letsencrypt'% repo_url)
        local('cd letsencrypt && git fetch origin pull/%s/head:lePRtest'%PRnumstr)
        local('cd letsencrypt && git checkout lePRtest')
        if merge_master:
            local('cd letsencrypt && git remote update origin')
            local('cd letsencrypt && git merge origin/master -m "testmerge"')
        local('tar czf le.tar.gz letsencrypt')

def local_repo_to_remote():
    "copies local tarball of repo to remote"
    with lcd(LOGDIR):
        put(local_path='le.tar.gz', remote_path='')
        run('tar xzf le.tar.gz')

def local_repo_clean():
    "delete tarball"
    with lcd(LOGDIR):
        local('rm le.tar.gz')

def deploy_script(scriptpath, *args):
    "copies to remote and executes local script"
    #with lcd('scripts'):
    put(local_path=scriptpath, remote_path='', mirror_local_mode=True)
    scriptfile = os.path.split(scriptpath)[1]
    args_str = ' '.join(args)
    run('./'+scriptfile+' '+args_str)

def run_boulder():
    with cd('$GOPATH/src/github.com/letsencrypt/boulder'):
        run('go run cmd/rabbitmq-setup/main.go -server amqp://localhost')
        run('nohup ./start.py >& /dev/null < /dev/null &')

def config_and_launch_boulder(instance):
    execute(deploy_script, 'scripts/boulder_config.sh')
    execute(run_boulder)

def install_and_launch_certbot(instance, boulder_url, target):
    execute(local_repo_to_remote)
    with shell_env(BOULDER_URL=boulder_url,
                   PUBLIC_IP=instance.public_ip_address,
                   PRIVATE_IP=instance.private_ip_address,
                   PUBLIC_HOSTNAME=instance.public_dns_name,
                   PIP_EXTRA_INDEX_URL=cl_args.alt_pip,
                   OS_TYPE=target['type']):
        execute(deploy_script, cl_args.test_script)

def grab_certbot_log():
    "grabs letsencrypt.log via cat into logged stdout"
    sudo('if [ -f /var/log/letsencrypt/letsencrypt.log ]; then \
    cat /var/log/letsencrypt/letsencrypt.log; else echo "[novarlog]"; fi')
    # fallback file if /var/log is unwriteable...? correct?
    sudo('if [ -f ./certbot.log ]; then \
    cat ./certbot.log; else echo "[nolocallog]"; fi')

def create_client_instances(targetlist, security_group_id, subnet_id):
    "Create a fleet of client instances"
    instances = []
    print("Creating instances: ", end="")
    for target in targetlist:
        if target['virt'] == 'hvm':
            machine_type = 't2.medium' if cl_args.fast else 't2.micro'
        else:
            # 32 bit systems
            machine_type = 'c1.medium' if cl_args.fast else 't1.micro'
        if 'userdata' in target.keys():
            userdata = target['userdata']
        else:
            userdata = ''
        name = 'le-%s'%target['name']
        print(name, end=" ")
        instances.append(make_instance(name,
                                       target['ami'],
                                       KEYNAME,
                                       machine_type=machine_type,
                                       security_group_id=security_group_id,
                                       subnet_id=subnet_id,
                                       userdata=userdata))
    print()
    return instances


def test_client_process(inqueue, outqueue):
    cur_proc = mp.current_process()
    for inreq in iter(inqueue.get, SENTINEL):
        ii, target = inreq

        #save all stdout to log file
        sys.stdout = open(LOGDIR+'/'+'%d_%s.log'%(ii,target['name']), 'w')

        print("[%s : client %d %s %s]" % (cur_proc.name, ii, target['ami'], target['name']))
        instances[ii] = block_until_instance_ready(instances[ii])
        print("server %s at %s"%(instances[ii], instances[ii].public_ip_address))
        env.host_string = "%s@%s"%(target['user'], instances[ii].public_ip_address)
        print(env.host_string)

        try:
            install_and_launch_certbot(instances[ii], boulder_url, target)
            outqueue.put((ii, target, 'pass'))
            print("%s - %s SUCCESS"%(target['ami'], target['name']))
        except:
            outqueue.put((ii, target, 'fail'))
            print("%s - %s FAIL"%(target['ami'], target['name']))
            traceback.print_exc(file=sys.stdout)
            pass

        # append server certbot.log to each per-machine output log
        print("\n\ncertbot.log\n" + "-"*80 + "\n")
        try:
            execute(grab_certbot_log)
        except:
            print("log fail\n")
            traceback.print_exc(file=sys.stdout)
            pass


def cleanup(cl_args, instances, targetlist):
    print('Logs in ', LOGDIR)
    if not cl_args.saveinstances:
        print('Terminating EC2 Instances')
        if cl_args.killboulder:
            boulder_server.terminate()
        for instance in instances:
            instance.terminate()
    else:
        # print login information for the boxes for debugging
        for ii, target in enumerate(targetlist):
            print(target['name'],
                  target['ami'],
                  "%s@%s"%(target['user'], instances[ii].public_ip_address))



#-------------------------------------------------------------------------------
# SCRIPT BEGINS
#-------------------------------------------------------------------------------

# Fabric library controlled through global env parameters
env.key_filename = KEYFILE
env.shell = '/bin/bash -l -i -c'
env.connection_attempts = 5
env.timeout = 10
# replace default SystemExit thrown by fabric during trouble
class FabricException(Exception):
    pass
env['abort_exception'] = FabricException

# Set up local copy of git repo
#-------------------------------------------------------------------------------
LOGDIR = "letest-%d"%int(time.time())
print("Making local dir for test repo and logs: %s"%LOGDIR)
local('mkdir %s'%LOGDIR)

# figure out what git object to test and locally create it in LOGDIR
print("Making local git repo")
try:
    if cl_args.pull_request != '~':
        print('Testing PR %s '%cl_args.pull_request,
              "MERGING into master" if cl_args.merge_master else "")
        execute(local_git_PR, cl_args.repo, cl_args.pull_request, cl_args.merge_master)
    elif cl_args.branch != '~':
        print('Testing branch %s of %s'%(cl_args.branch, cl_args.repo))
        execute(local_git_branch, cl_args.repo, cl_args.branch)
    else:
        print('Testing master of %s'%cl_args.repo)
        execute(local_git_clone, cl_args.repo)
except FabricException:
    print("FAIL: trouble with git repo")
    traceback.print_exc()
    exit()


# Set up EC2 instances
#-------------------------------------------------------------------------------
configdata = yaml.load(open(cl_args.config_file, 'r'))
targetlist = configdata['targets']
print('Testing against these images: [%d total]'%len(targetlist))
for target in targetlist:
    print(target['ami'], target['name'])

print("Connecting to EC2 using\n profile %s\n keyname %s\n keyfile %s"%(PROFILE, KEYNAME, KEYFILE))
AWS_SESSION = boto3.session.Session(profile_name=PROFILE)
EC2 = AWS_SESSION.resource('ec2')

print("Determining Subnet")
for subnet in EC2.subnets.all():
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
vpc = EC2.Vpc(vpc_id)
sg_exists = False
for sg in vpc.security_groups.all():
    if sg.group_name == SECURITY_GROUP_NAME:
        security_group_id = sg.id
        sg_exists = True
        print("  %s already exists"%SECURITY_GROUP_NAME)
if not sg_exists:
    security_group_id = make_security_group(vpc).id
    time.sleep(30)

boulder_preexists = False
boulder_servers = EC2.instances.filter(Filters=[
    {'Name': 'tag:Name',            'Values': ['le-boulderserver']},
    {'Name': 'instance-state-name', 'Values': ['running']}])

boulder_server = next(iter(boulder_servers), None)

print("Requesting Instances...")
if boulder_server:
    print("Found existing boulder server:", boulder_server)
    boulder_preexists = True
else:
    print("Can't find a boulder server, starting one...")
    boulder_server = make_instance('le-boulderserver',
                                   BOULDER_AMI,
                                   KEYNAME,
                                   machine_type='t2.micro',
                                   #machine_type='t2.medium',
                                   security_group_id=security_group_id,
                                   subnet_id=subnet_id)

try:
    if not cl_args.boulderonly:
        instances = create_client_instances(targetlist, security_group_id, subnet_id)

    # Configure and launch boulder server
    #-------------------------------------------------------------------------------
    print("Waiting on Boulder Server")
    boulder_server = block_until_instance_ready(boulder_server)
    print(" server %s"%boulder_server)


    # env.host_string defines the ssh user and host for connection
    env.host_string = "ubuntu@%s"%boulder_server.public_ip_address
    print("Boulder Server at (SSH):", env.host_string)
    if not boulder_preexists:
        print("Configuring and Launching Boulder")
        config_and_launch_boulder(boulder_server)
        # blocking often unnecessary, but cheap EC2 VMs can get very slow
        block_until_http_ready('http://%s:4000'%boulder_server.public_ip_address,
                               wait_time=10, timeout=500)

    boulder_url = "http://%s:4000/directory"%boulder_server.private_ip_address
    print("Boulder Server at (public ip): http://%s:4000/directory"%boulder_server.public_ip_address)
    print("Boulder Server at (EC2 private ip): %s"%boulder_url)

    if cl_args.boulderonly:
        sys.exit(0)

    # Install and launch client scripts in parallel
    #-------------------------------------------------------------------------------
    print("Uploading and running test script in parallel: %s"%cl_args.test_script)
    print("Output routed to log files in %s"%LOGDIR)
    # (Advice: always use Manager.Queue, never regular multiprocessing.Queue
    # the latter has implementation flaws that deadlock it in some circumstances)
    manager = Manager()
    outqueue = manager.Queue()
    inqueue = manager.Queue()
    SENTINEL = None #queue kill signal

    # launch as many processes as clients to test
    num_processes = len(targetlist)
    jobs = [] #keep a reference to current procs


    # initiate process execution
    for i in range(num_processes):
        p = mp.Process(target=test_client_process, args=(inqueue, outqueue))
        jobs.append(p)
        p.daemon = True  # kills subprocesses if parent is killed
        p.start()

    # fill up work queue
    for ii, target in enumerate(targetlist):
        inqueue.put((ii, target))

    # add SENTINELs to end client processes
    for i in range(num_processes):
        inqueue.put(SENTINEL)
    # wait on termination of client processes
    for p in jobs:
        p.join()
    # add SENTINEL to output queue
    outqueue.put(SENTINEL)

    # clean up
    execute(local_repo_clean)

    # print and save summary results
    results_file = open(LOGDIR+'/results', 'w')
    outputs = [outq for outq in iter(outqueue.get, SENTINEL)]
    outputs.sort(key=lambda x: x[0])
    for outq in outputs:
        ii, target, status = outq
        print('%d %s %s'%(ii, target['name'], status))
        results_file.write('%d %s %s\n'%(ii, target['name'], status))
    if len(outputs) != num_processes:
        failure_message = 'FAILURE: Some target machines failed to run and were not tested. ' +\
            'Tests should be rerun.'
        print(failure_message)
        results_file.write(failure_message + '\n')
    results_file.close()

finally:
    cleanup(cl_args, instances, targetlist)

    # kill any connections
    fabric.network.disconnect_all()
