"""Utilities for all Let's Encrypt."""
import base64
import grp
import errno
import os
import pwd
import stat
import sys

from letsencrypt.client import logger


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

# Quick implementations of b64 url safe encode/decode
# We will include a proper library in the future if the library
# doesn't conflict with our existing dependencies
def b64_url_enc(s):
    try:
        s = s.encode("utf8")
    except:
        pass

    i = base64.urlsafe_b64encode(s)
    return i.rstrip("=")

def b64_url_dec(s):
    try:
        s = s.encode("utf8")
    except:
        pass

    pad = '=' * (4 - (len(s) % 4))
    return base64.urlsafe_b64decode(s + pad)
