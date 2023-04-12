""" Entry point for Apache Plugin """
from typing import Dict
from typing import Type

from certbot import util
from certbot_apache._internal import configurator
from certbot_apache._internal import override_arch
from certbot_apache._internal import override_centos
from certbot_apache._internal import override_darwin
from certbot_apache._internal import override_debian
from certbot_apache._internal import override_fedora
from certbot_apache._internal import override_gentoo
from certbot_apache._internal import override_suse
from certbot_apache._internal import override_void

OVERRIDE_CLASSES: Dict[str, Type[configurator.ApacheConfigurator]] = {
    "arch": override_arch.ArchConfigurator,
    "cloudlinux": override_centos.CentOSConfigurator,
    "darwin": override_darwin.DarwinConfigurator,
    "debian": override_debian.DebianConfigurator,
    "ubuntu": override_debian.DebianConfigurator,
    "centos": override_centos.CentOSConfigurator,
    "centos linux": override_centos.CentOSConfigurator,
    "fedora_old": override_centos.CentOSConfigurator,
    "fedora": override_fedora.FedoraConfigurator,
    "linuxmint": override_debian.DebianConfigurator,
    "ol": override_centos.CentOSConfigurator,
    "oracle": override_centos.CentOSConfigurator,
    "redhatenterpriseserver": override_centos.CentOSConfigurator,
    "red hat enterprise linux server": override_centos.CentOSConfigurator,
    "rhel": override_centos.CentOSConfigurator,
    "amazon": override_centos.CentOSConfigurator,
    "gentoo": override_gentoo.GentooConfigurator,
    "gentoo base system": override_gentoo.GentooConfigurator,
    "opensuse": override_suse.OpenSUSEConfigurator,
    "suse": override_suse.OpenSUSEConfigurator,
    "sles": override_suse.OpenSUSEConfigurator,
    "scientific": override_centos.CentOSConfigurator,
    "scientific linux": override_centos.CentOSConfigurator,
    "void": override_void.VoidConfigurator,
}


def get_configurator() -> Type[configurator.ApacheConfigurator]:
    """ Get correct configurator class based on the OS fingerprint """
    os_name, os_version = util.get_os_info()
    os_name = os_name.lower()
    override_class = None

    # Special case for older Fedora versions
    min_version = util.LooseVersion('29')
    if os_name == 'fedora' and util.LooseVersion(os_version).try_risky_less(min_version):
        os_name = 'fedora_old'

    try:
        override_class = OVERRIDE_CLASSES[os_name]
    except KeyError:
        # OS not found in the list
        os_like = util.get_systemd_os_like()
        if os_like:
            for os_name in os_like:
                override_class = OVERRIDE_CLASSES.get(os_name)
        if not override_class:
            # No override class found, return the generic configurator
            override_class = configurator.ApacheConfigurator
    return override_class


ENTRYPOINT = get_configurator()
