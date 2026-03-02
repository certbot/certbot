""" Distribution specific override class for Void Linux """
from certbot_apache._internal import configurator
from certbot_apache._internal.configurator import OsOptions


class VoidConfigurator(configurator.ApacheConfigurator):
    """Void Linux specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        server_root="/etc/apache",
        vhost_root="/etc/apache/extra",
        vhost_files="*.conf",
        logs_root="/var/log/httpd",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        challenge_location="/etc/apache/extra",
    )
