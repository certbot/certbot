""" Distribution specific override class for OpenSUSE """
import pkg_resources

import zope.interface

from certbot import interfaces

from certbot_apache import configurator

@zope.interface.provider(interfaces.IPluginFactory)
class OpenSUSEConfigurator(configurator.ApacheConfigurator):
    """OpenSUSE specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/vhosts.d",
        vhost_files="*.conf",
        logs_root="/var/log/apache2",
        version_cmd=['apache2ctl', '-v'],
        apache_cmd="apache2ctl",
        restart_cmd=['apache2ctl', 'graceful'],
        conftest_cmd=['apache2ctl', 'configtest'],
        enmod="a2enmod",
        dismod="a2dismod",
        le_vhost_ext="-le-ssl.conf",
        handle_mods=False,
        handle_sites=False,
        challenge_location="/etc/apache2/vhosts.d",
        MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
            "certbot_apache", "options-ssl-apache.conf")
    )
