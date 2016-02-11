"""Plugin common functions."""
import os
import pkg_resources
import re
import shutil
import tempfile

import OpenSSL
import zope.interface

from acme.jose import util as jose_util

from letsencrypt import constants
from letsencrypt import interfaces
from letsencrypt import le_util


def option_namespace(name):
    """ArgumentParser options namespace (prefix of all options)."""
    return name + "-"


def dest_namespace(name):
    """ArgumentParser dest namespace (prefix of all destinations)."""
    return name.replace("-", "_") + "_"

private_ips_regex = re.compile(
    r"(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|"
    r"(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
hostname_regex = re.compile(
    r"^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*[a-z]+$", re.IGNORECASE)


class Plugin(object):
    """Generic plugin."""
    zope.interface.implements(interfaces.IPlugin)
    # classProvides is not inherited, subclasses must define it on their own
    #zope.interface.classProvides(interfaces.IPluginFactory)

    def __init__(self, config, name):
        self.config = config
        self.name = name

    @jose_util.abstractclassmethod
    def add_parser_arguments(cls, add):
        """Add plugin arguments to the CLI argument parser.

        :param callable add: Function that proxies calls to
            `argparse.ArgumentParser.add_argument` prepending options
            with unique plugin name prefix.

        NOTE: if you add argpase arguments such that users setting them can
        create a config entry that python's bool() would consider false (ie,
        the use might set the variable to "", [], 0, etc), please ensure that
        cli._set_by_cli() works for your variable.

        """

    @classmethod
    def inject_parser_options(cls, parser, name):
        """Inject parser options.

        See `~.IPlugin.inject_parser_options` for docs.

        """
        # dummy function, doesn't check if dest.startswith(self.dest_namespace)
        def add(arg_name_no_prefix, *args, **kwargs):
            # pylint: disable=missing-docstring
            return parser.add_argument(
                "--{0}{1}".format(option_namespace(name), arg_name_no_prefix),
                *args, **kwargs)
        return cls.add_parser_arguments(add)

    @property
    def option_namespace(self):
        """ArgumentParser options namespace (prefix of all options)."""
        return option_namespace(self.name)

    def option_name(self, name):
        """Option name (include plugin namespace)."""
        return self.option_namespace + name

    @property
    def dest_namespace(self):
        """ArgumentParser dest namespace (prefix of all destinations)."""
        return dest_namespace(self.name)

    def dest(self, var):
        """Find a destination for given variable ``var``."""
        # this should do exactly the same what ArgumentParser(arg),
        # does to "arg" to compute "dest"
        return self.dest_namespace + var.replace("-", "_")

    def conf(self, var):
        """Find a configuration value for variable ``var``."""
        return getattr(self.config, self.dest(var))
# other


class Addr(object):
    r"""Represents an virtual host address.

    :param str addr: addr part of vhost address
    :param str port: port number or \*, or ""

    """
    def __init__(self, tup):
        self.tup = tup

    @classmethod
    def fromstring(cls, str_addr):
        """Initialize Addr from string."""
        tup = str_addr.partition(':')
        return cls((tup[0], tup[2]))

    def __str__(self):
        if self.tup[1]:
            return "%s:%s" % self.tup
        return self.tup[0]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.tup == other.tup
        return False

    def __hash__(self):
        return hash(self.tup)

    def get_addr(self):
        """Return addr part of Addr object."""
        return self.tup[0]

    def get_port(self):
        """Return port."""
        return self.tup[1]

    def get_addr_obj(self, port):
        """Return new address object with same addr and new port."""
        return self.__class__((self.tup[0], port))


class TLSSNI01(object):
    """Abstract base for TLS-SNI-01 challenge performers"""

    def __init__(self, configurator):
        self.configurator = configurator
        self.achalls = []
        self.indices = []
        self.challenge_conf = os.path.join(
            configurator.config.config_dir, "le_tls_sni_01_cert_challenge.conf")
        # self.completed = 0

    def add_chall(self, achall, idx=None):
        """Add challenge to TLSSNI01 object to perform at once.

        :param .KeyAuthorizationAnnotatedChallenge achall: Annotated
            TLSSNI01 challenge.

        :param int idx: index to challenge in a larger array

        """
        self.achalls.append(achall)
        if idx is not None:
            self.indices.append(idx)

    def get_cert_path(self, achall):
        """Returns standardized name for challenge certificate.

        :param .KeyAuthorizationAnnotatedChallenge achall: Annotated
            tls-sni-01 challenge.

        :returns: certificate file name
        :rtype: str

        """
        return os.path.join(self.configurator.config.work_dir,
                            achall.chall.encode("token") + ".crt")

    def get_key_path(self, achall):
        """Get standardized path to challenge key."""
        return os.path.join(self.configurator.config.work_dir,
                            achall.chall.encode("token") + '.pem')

    def _setup_challenge_cert(self, achall, cert_key=None):

        """Generate and write out challenge certificate."""
        cert_path = self.get_cert_path(achall)
        key_path = self.get_key_path(achall)
        # Register the path before you write out the file
        self.configurator.reverter.register_file_creation(True, key_path)
        self.configurator.reverter.register_file_creation(True, cert_path)

        response, (cert, key) = achall.response_and_validation(
            cert_key=cert_key)
        cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        key_pem = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key)

        # Write out challenge cert and key
        with open(cert_path, "wb") as cert_chall_fd:
            cert_chall_fd.write(cert_pem)
        with le_util.safe_open(key_path, 'wb', chmod=0o400) as key_file:
            key_file.write(key_pem)

        return response


# test utils used by letsencrypt_apache/letsencrypt_nginx (hence
# "pragma: no cover") TODO: this might quickly lead to dead code (also
# c.f. #383)

def setup_ssl_options(config_dir, src, dest):  # pragma: no cover
    """Move the ssl_options into position and return the path."""
    option_path = os.path.join(config_dir, dest)
    shutil.copyfile(src, option_path)
    return option_path


def dir_setup(test_dir, pkg):  # pragma: no cover
    """Setup the directories necessary for the configurator."""
    temp_dir = tempfile.mkdtemp("temp")
    config_dir = tempfile.mkdtemp("config")
    work_dir = tempfile.mkdtemp("work")

    os.chmod(temp_dir, constants.CONFIG_DIRS_MODE)
    os.chmod(config_dir, constants.CONFIG_DIRS_MODE)
    os.chmod(work_dir, constants.CONFIG_DIRS_MODE)

    test_configs = pkg_resources.resource_filename(
        pkg, os.path.join("testdata", test_dir))

    shutil.copytree(
        test_configs, os.path.join(temp_dir, test_dir), symlinks=True)

    return temp_dir, config_dir, work_dir
