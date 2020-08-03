""" Distribution specific override class for macOS """
import zope.interface

from certbot import interfaces
from certbot_apache._internal import configurator


@zope.interface.provider(interfaces.IPluginFactory)
class DarwinConfigurator(configurator.ApacheConfigurator):
    """macOS specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/other",
        vhost_files="*.conf",
        logs_root="/var/log/apache2",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_modules=False,
        handle_sites=False,
        challenge_location="/etc/apache2/other",
        bin=None,
    )
