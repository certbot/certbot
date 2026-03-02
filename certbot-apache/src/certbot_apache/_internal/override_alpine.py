""" Distribution specific override class for Alpine Linux """
from certbot_apache._internal import configurator
from certbot_apache._internal.configurator import OsOptions


class AlpineConfigurator(configurator.ApacheConfigurator):
    """Alpine Linux specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/conf.d",
        vhost_files="*.conf",
        logs_root="/var/log/apache2",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        challenge_location="/etc/apache2/conf.d",
    )
