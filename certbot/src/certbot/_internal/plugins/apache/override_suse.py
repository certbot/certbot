""" Distribution specific override class for OpenSUSE """
from certbot._internal.plugins.apache import configurator
from certbot._internal.plugins.apache.configurator import OsOptions


class OpenSUSEConfigurator(configurator.ApacheConfigurator):
    """OpenSUSE specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        vhost_root="/etc/apache2/vhosts.d",
        vhost_files="*.conf",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod="a2enmod",
        dismod="a2dismod",
        challenge_location="/etc/apache2/vhosts.d",
    )
