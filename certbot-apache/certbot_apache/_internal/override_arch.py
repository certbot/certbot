""" Distribution specific override class for Arch Linux """
import pkg_resources

import zope.interface

from certbot import interfaces

from certbot_apache import configurator

@zope.interface.provider(interfaces.IPluginFactory)
class ArchConfigurator(configurator.ApacheConfigurator):
    """Arch Linux specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/httpd",
        vhost_root="/etc/httpd/conf",
        vhost_files="*.conf",
        logs_root="/var/log/httpd",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_modules=False,
        handle_sites=False,
        challenge_location="/etc/httpd/conf",
        MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
            "certbot_apache", "options-ssl-apache.conf")
    )
