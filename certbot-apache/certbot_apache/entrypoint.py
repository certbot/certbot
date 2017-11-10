""" Entry point for Apache Plugin """
from certbot import util

from certbot_apache import configurator
from certbot_apache import override_debian
from certbot_apache import override_centos
from certbot_apache import override_gentoo

from certbot_apache.override import OVERRIDE_CLASSES

def get_configurator():
    os_info = util.get_os_info()
    override_class = None
    try:
        override_class = OVERRIDE_CLASSES[os_info[0].lower()]
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
