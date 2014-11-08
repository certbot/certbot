# This file will contain functions useful for all Trustify Classes
import errno
import stat
import os, pwd, grp
import M2Crypto
import time
from M2Crypto import EVP, X509, RSA, ASN1
from trustify.client import logger
#import logger


def make_csr(key_file, domains):
    """
    Returns new CSR in PEM and DER form using key_file containing all domains
    """
    assert domains, "Must provide one or more hostnames for the CSR."
    rsa_key = M2Crypto.RSA.load_key(key_file)
    pk = EVP.PKey()
    pk.assign_rsa(rsa_key)
    
    x = X509.Request()
    x.set_pubkey(pk)
    name = x.get_subject()
    name.CN = domains[0]

    extstack = X509.X509_Extension_Stack()
    ext = X509.new_extension('subjectAltName', ", ".join(["DNS:%s" % d for d in domains]))

    extstack.push(ext)
    x.add_extensions(extstack)
    x.sign(pk,'sha256')
    assert x.verify(pk)
    pk2 = x.get_pubkey()
    assert x.verify(pk2)
    return x.as_pem(), x.as_der()

def make_ss_cert(key_file, domains):
    """
    Returns new self-signed cert in PEM form using key_file containing all domains
    """
    assert domains, "Must provide one or more hostnames for the CSR."
    rsa_key = M2Crypto.RSA.load_key(key_file)
    pk = EVP.PKey()
    pk.assign_rsa(rsa_key)
    
    x = X509.X509()
    x.set_pubkey(pk)
    x.set_serial_number(1337)
    x.set_version(2)

    t = long(time.time())
    current = ASN1.ASN1_UTCTIME()
    current.set_time(t)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time((7 * 24 * 60 * 60) + t)
    x.set_not_before(current)
    x.set_not_after(expire)

    name = x.get_subject()
    name.C = "US"
    name.ST = "Michigan"
    name.L = "Ann Arbor"
    name.O = "University of Michigan and the EFF"
    name.CN = domains[0]
    x.set_issuer(x.get_subject())

    x.add_ext(X509.new_extension('basicConstraints', 'CA:FALSE'))
    #x.add_ext(X509.new_extension('extendedKeyUsage', 'TLS Web Server Authentication'))
    x.add_ext(X509.new_extension('subjectAltName', ", ".join(["DNS:%s" % d for d in domains])))
    
    x.sign(pk, 'sha256')
    assert x.verify(pk)
    assert x.verify()
    #print check_purpose(,0
    return x.as_pem()
    
def make_or_verify_dir(directory, permissions=0755, uid=0):
    try:
        os.makedirs(directory, permissions)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if not check_permissions(directory, permissions, uid):
                logger.fatal("%s exists and does not contain the proper permissions or owner" % directory)
                sys.exit(57)
        else:
            raise

def check_permissions(filepath, mode, uid=0):
    file_stat = os.stat(filepath)
    if stat.S_IMODE(file_stat.st_mode) != mode:
        return False
    return file_stat.st_uid == uid

def unique_file(default_name, mode = 0777):
    """
    Safely finds a unique file for writing only (by default)
    """
    count = 1
    f_parsed = os.path.splitext(default_name)
    while 1:
        try:
            fd = os.open(default_name, os.O_CREAT|os.O_EXCL|os.O_RDWR, mode)
            return os.fdopen(fd, 'w'), default_name
        except OSError:
            pass
        default_name = f_parsed[0] + '_' + str(count) + f_parsed[1]
        count += 1

def drop_privs():
    nogroup = grp.getgrnam("nogroup").gr_gid
    nobody = pwd.getpwnam("nobody").pw_uid
    os.setgid(nogroup)
    os.setgroups([])
    os.setuid(nobody)
