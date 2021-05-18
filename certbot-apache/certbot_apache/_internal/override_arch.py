""" Distribution specific override class for Arch Linux """
import zope.interface

from certbot import interfaces
from certbot_apache._internal import configurator
from certbot_apache._internal.configurator import OsOptions


@zope.interface.provider(interfaces.IPluginFactory)
class ArchConfigurator(configurator.ApacheConfigurator):
    """Arch Linux specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        server_root="/etc/httpd",
        vhost_root="/etc/httpd/conf",
        vhost_files="*.conf",
        logs_root="/var/log/httpd",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        challenge_location="/etc/httpd/conf",
    )
