""" Entry point for Apache Plugin """
from typing import Dict
from typing import Type

from certbot_apache._internal import configurator
from certbot_apache._internal import override_arch
from certbot_apache._internal import override_centos
from certbot_apache._internal import override_darwin
from certbot_apache._internal import override_debian
from certbot_apache._internal import override_fedora
from certbot_apache._internal import override_gentoo
from certbot_apache._internal import override_suse
from certbot_apache._internal import override_void

from certbot import util

OVERRIDE_CLASSES: Dict[str, Type[configurator.ApacheConfigurator]] = {
    "arch": override_arch.ArchConfigurator,
    "darwin": override_darwin.DarwinConfigurator,
    "debian": override_debian.DebianConfigurator,
    "ubuntu": override_debian.DebianConfigurator,
    "fedora": override_fedora.FedoraConfigurator,
    "linuxmint": override_debian.DebianConfigurator,
    "amazon": override_centos.CentOSConfigurator,
    "gentoo": override_gentoo.GentooConfigurator,
    "gentoo base system": override_gentoo.GentooConfigurator,
    "opensuse": override_suse.OpenSUSEConfigurator,
    "suse": override_suse.OpenSUSEConfigurator,
    "sles": override_suse.OpenSUSEConfigurator,
    "void": override_void.VoidConfigurator,
}


def rhel_derived_os(os_name: str) -> bool:
    """
    Returns whether the given OS is RHEL derived, i.e. tracks RHEL's versioning
    scheme, and thus should use our CentOS configurator
    """
    return os_name in [
        "centos", "centos linux",
        "cloudlinux",
        "ol", "oracle",
        "rhel", "redhatenterpriseserver", "red hat enterprise linux server",
        "scientific", "scientific linux",
    ]


def get_configurator() -> Type[configurator.ApacheConfigurator]:
    """ Get correct configurator class based on the OS fingerprint """
    os_name, os_version = util.get_os_info()
    os_name = os_name.lower()
    override_class = None

    # Special case for older Fedora versions
    min_version = util.parse_loose_version('29')
    if os_name == 'fedora' and util.parse_loose_version(os_version) < min_version:
        return override_centos.OldCentOSConfigurator

    # For CentOS and other RHEL-like distros (that use RHEL's versioning
    # scheme), Apache's behavior changed in RHEL v9 (see issue #9386). Determine
    # whether we're using the newer or older overrides class based on the version
    if rhel_derived_os(os_name):
        old = util.parse_loose_version(os_version) < util.parse_loose_version('9')
        if old:
            return override_centos.OldCentOSConfigurator
        else:
            return override_centos.CentOSConfigurator

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
