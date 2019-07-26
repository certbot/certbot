""" Entry point for Apache Plugin """
# Pylint does not like disutils.version when running inside a venv.
# See: https://github.com/PyCQA/pylint/issues/73
from distutils.version import LooseVersion  # pylint: disable=no-name-in-module,import-error

from certbot import util

from certbot_apache import configurator
from certbot_apache import override_arch
from certbot_apache import override_fedora
from certbot_apache import override_darwin
from certbot_apache import override_debian
from certbot_apache import override_centos
from certbot_apache import override_gentoo
from certbot_apache import override_suse

OVERRIDE_CLASSES = {
    "arch": override_arch.ArchConfigurator,
    "darwin": override_darwin.DarwinConfigurator,
    "debian": override_debian.DebianConfigurator,
    "ubuntu": override_debian.DebianConfigurator,
    "centos": override_centos.CentOSConfigurator,
    "centos linux": override_centos.CentOSConfigurator,
    "fedora_old": override_centos.CentOSConfigurator,
    "fedora": override_fedora.FedoraConfigurator,
    "ol": override_centos.CentOSConfigurator,
    "red hat enterprise linux server": override_centos.CentOSConfigurator,
    "rhel": override_centos.CentOSConfigurator,
    "amazon": override_centos.CentOSConfigurator,
    "gentoo": override_gentoo.GentooConfigurator,
    "gentoo base system": override_gentoo.GentooConfigurator,
    "opensuse": override_suse.OpenSUSEConfigurator,
    "suse": override_suse.OpenSUSEConfigurator,
}


def get_configurator():
    """ Get correct configurator class based on the OS fingerprint """
    os_name, os_version = util.get_os_info()
    os_name = os_name.lower()
    override_class = None

    # Special case for older Fedora versions
    if os_name == 'fedora' and LooseVersion(os_version) < LooseVersion('29'):
        os_name = 'fedora_old'

    try:
        override_class = OVERRIDE_CLASSES[os_name]
    except KeyError:
        # OS not found in the list
        os_like = util.get_systemd_os_like()
        if os_like:
            for os_name in os_like:
                if os_name in OVERRIDE_CLASSES.keys():
                    override_class = OVERRIDE_CLASSES[os_name]
        if not override_class:
            # No override class found, return the generic configurator
            override_class = configurator.ApacheConfigurator
    return override_class


ENTRYPOINT = get_configurator()
