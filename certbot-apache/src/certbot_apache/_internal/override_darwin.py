""" Distribution specific override class for macOS """
from certbot_apache._internal import configurator
from certbot_apache._internal.configurator import OsOptions


class DarwinConfigurator(configurator.ApacheConfigurator):
    """macOS specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        vhost_root="/etc/apache2/other",
        vhost_files="*.conf",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        challenge_location="/etc/apache2/other",
    )
