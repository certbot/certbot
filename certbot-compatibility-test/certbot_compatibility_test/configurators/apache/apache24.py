"""Proxies ApacheConfigurator for Apache 2.4 tests"""

import zope.interface

from certbot_compatibility_test import errors
from certbot_compatibility_test import interfaces
from certbot_compatibility_test.configurators.apache import common as apache_common


# The docker image doesn't actually have the watchdog module, but unless the
# config uses mod_heartbeat or mod_heartmonitor (which aren't installed and
# therefore the config won't be loaded), I believe this isn't a problem
# http://httpd.apache.org/docs/2.4/mod/mod_watchdog.html
STATIC_MODULES = set(["core", "so", "http", "mpm_event", "watchdog"])


SHARED_MODULES = {
    "log_config", "logio", "version", "unixd", "access_compat", "actions",
    "alias", "allowmethods", "auth_basic", "auth_digest", "auth_form",
    "authn_anon", "authn_core", "authn_dbd", "authn_dbm", "authn_file",
    "authn_socache", "authnz_ldap", "authz_core", "authz_dbd", "authz_dbm",
    "authz_groupfile", "authz_host", "authz_owner", "authz_user", "autoindex",
    "buffer", "cache", "cache_disk", "cache_socache", "cgid", "dav", "dav_fs",
    "dbd", "deflate", "dir", "dumpio", "env", "expires", "ext_filter",
    "file_cache", "filter", "headers", "include", "info", "lbmethod_bybusyness",
    "lbmethod_byrequests", "lbmethod_bytraffic", "lbmethod_heartbeat", "ldap",
    "log_debug", "macro", "mime", "negotiation", "proxy", "proxy_ajp",
    "proxy_balancer", "proxy_connect", "proxy_express", "proxy_fcgi",
    "proxy_ftp", "proxy_http", "proxy_scgi", "proxy_wstunnel", "ratelimit",
    "remoteip", "reqtimeout", "request", "rewrite", "sed", "session",
    "session_cookie", "session_crypto", "session_dbd", "setenvif",
    "slotmem_shm", "socache_dbm", "socache_memcache", "socache_shmcb",
    "speling", "ssl", "status", "substitute", "unique_id", "userdir",
    "vhost_alias"}


@zope.interface.implementer(interfaces.IConfiguratorProxy)
class Proxy(apache_common.Proxy):
    """Wraps the ApacheConfigurator for Apache 2.4 tests"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super(Proxy, self).__init__(args)
        # Running init isn't ideal, but the Docker container needs to survive
        # Apache restarts
        self.start_docker("bradmw/apache2.4", "init")

    def preprocess_config(self, server_root):
        """Prepares the configuration for use in the Docker"""
        super(Proxy, self).preprocess_config(server_root)
        if self.version[1] != 4:
            raise errors.Error("Apache version not 2.4")

        with open(self.test_conf, "a") as f:
            for module in self.modules:
                if module not in STATIC_MODULES:
                    if module in SHARED_MODULES:
                        f.write(
                            "LoadModule {0}_module /usr/local/apache2/modules/"
                            "mod_{0}.so\n".format(module))
                    else:
                        raise errors.Error(
                            "Unsupported module {0}".format(module))
